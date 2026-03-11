"""
agent_loop.py — Main autonomous AI agent loop
AI thinks → plans → acts → learns → loops until done
"""
import asyncio
import json
import os
import time
from datetime import datetime
from typing import Dict, Optional

from core.ai_brain import AIBrain, ContextBuilder
from core.chain_detector import ChainDetector, FindingVerifier
from core.logger import Logger
from core.database import Database
from protocols.http_client import HTTPClient
from engines.engines import get_engine, ENGINE_REGISTRY


SYSTEM_PROMPT = """You are an autonomous penetration testing AI agent.
You are testing a web application WITH EXPLICIT AUTHORIZATION.
Your job: find security vulnerabilities and report them.

You receive the current scan state and MUST return a single JSON action.
Return ONLY valid JSON. No explanation outside JSON.

Priority order: AUTH > PAYMENT > ADMIN > PROFILE/API > NORMAL
Never repeat an already-executed action.
When all high-priority endpoints tested with confidence, return {"action":"done"}.

Available actions:
- run_engine: run a specific attack engine
- test_endpoint: test one endpoint with one engine
- generate_report: generate final HTML report
- done: scan complete

Valid engines: """ + ", ".join(ENGINE_REGISTRY.keys()) + """

Required JSON format:
{
  "action": "run_engine",
  "engine": "e12_idor_engine",
  "params": {"endpoint": "...", "method": "GET"},
  "reason": "why testing this",
  "priority": "HIGH",
  "confidence": 75
}"""


class AgentLoop:
    def __init__(self, config: dict, db: Database, http: HTTPClient,
                 rules: dict, logger: Logger):
        self.config = config
        self.db = db
        self.http = http
        self.rules = rules
        self.log = logger
        self.brain = AIBrain(config, logger)
        self.chain_detector = ChainDetector(db, logger)
        self.verifier = FindingVerifier(http, db, logger)
        self.iterations = 0
        self.max_iterations = config.get("max_iterations", 200)
        self.start_time = time.time()
        self.max_time = config.get("max_time_minutes", 120) * 60
        self.no_finding_streak = 0
        self.max_no_finding_streak = 30

    async def run(self) -> Dict:
        """Main agent loop — runs until done or limits hit"""
        self.log.phase("AGENT LOOP STARTED")

        while True:
            self.iterations += 1

            # Check stop conditions
            if self.iterations > self.max_iterations:
                self.log.warn(f"Max iterations ({self.max_iterations}) reached")
                break

            if time.time() - self.start_time > self.max_time:
                self.log.warn("Max scan time reached")
                break

            if self.no_finding_streak > self.max_no_finding_streak:
                self.log.warn(f"No new findings in last {self.max_no_finding_streak} actions")
                break

            # Check if all nodes tested
            untested = self.db.get_untested_nodes(limit=5)
            if not untested:
                self.log.info("All discovered endpoints have been tested")
                break

            self.log.info(f"[Loop {self.iterations}] Untested endpoints: {len(untested)}")

            # Build context (smart trimming — no context overflow)
            context_str = ContextBuilder.build(self.db, self.rules)

            # AI Decision
            t0 = time.time()
            decision = self.brain.decide(context_str, SYSTEM_PROMPT)
            decision_time = int((time.time() - t0) * 1000)

            action = decision.get("action", "done")
            engine_name = decision.get("engine", "")
            params = decision.get("params", {})
            reason = decision.get("reason", "")
            confidence = decision.get("confidence", 70)
            model = decision.get("_model", "rule-based")

            self.log.ai_decision(action, engine_name, reason, confidence)

            # Log AI decision
            self.db.log_action(
                action=action, engine=engine_name, params=params,
                reason=reason, ai_model=model, confidence=confidence
            )

            if action == "done":
                self.log.info("AI decided: scan complete")
                break

            # Validate: don't repeat same action
            if self.db.action_exists(action, engine_name, params):
                self.log.debug(f"Skipping duplicate action: {engine_name}")
                self.no_finding_streak += 1
                continue

            # Execute action
            findings_before = len(self.db.get_findings())
            result = await self._execute_action(action, engine_name, params)
            findings_after = len(self.db.get_findings())

            # Track no-finding streak
            if findings_after > findings_before:
                self.no_finding_streak = 0
                # Run chain detection on new findings
                new_chains = self.chain_detector.detect()
                if new_chains:
                    for chain in new_chains:
                        self.log.chain(chain["name"], chain["severity"])
            else:
                self.no_finding_streak += 1

            # Mark endpoint as tested
            endpoint_url = params.get("endpoint") or params.get("url")
            if endpoint_url:
                c = self.db.conn.cursor()
                c.execute("SELECT id FROM nodes WHERE url=? LIMIT 1", (endpoint_url,))
                row = c.fetchone()
                if row:
                    self.db.mark_node_tested(row["id"])

            # Checkpoint DB every 10 iterations
            if self.iterations % 10 == 0:
                self.db.checkpoint()
                stats = self.db.get_stats()
                self.log.stats({
                    "Iteration": self.iterations,
                    "Endpoints tested": f"{stats['tested_nodes']}/{stats['total_nodes']}",
                    "Findings": f"{stats['verified_findings']} verified / {stats['total_findings']} total",
                    "Critical": stats["critical"],
                    "High": stats["high"],
                    "Chains": stats["chains"],
                    "AI model": model,
                    "Elapsed": f"{int(time.time()-self.start_time)}s"
                })

            await asyncio.sleep(0.5)  # Small delay between actions

        # Final stats
        stats = self.db.get_stats()
        self.log.stats({
            "SCAN COMPLETE": "═" * 20,
            "Total iterations": self.iterations,
            "Endpoints found": stats["total_nodes"],
            "Endpoints tested": stats["tested_nodes"],
            "Total findings": stats["total_findings"],
            "Verified findings": stats["verified_findings"],
            "Critical": stats["critical"],
            "High": stats["high"],
            "Medium": stats["medium"],
            "Attack chains": stats["chains"],
            "Total time": f"{int(time.time()-self.start_time)}s"
        })

        return {"status": "complete", "stats": stats}

    async def _execute_action(self, action: str, engine_name: str, params: dict) -> Optional[Dict]:
        """Execute AI decision — route to correct engine"""
        if action == "generate_report":
            return None  # Report generated separately

        if action in ["run_engine", "test_endpoint"]:
            engine = get_engine(engine_name, self.http, self.db, self.rules, self.log)
            if not engine:
                self.log.warn(f"Unknown engine: {engine_name}")
                return None

            try:
                result = await engine.run(params)

                # Process findings from engine
                if result and result.findings:
                    for f in result.findings:
                        # Add to DB
                        fid = self.db.add_finding(
                            vuln_type=f["vuln_type"],
                            severity=f["severity"],
                            endpoint=f["endpoint"],
                            description=f["description"],
                            param=f.get("param"),
                            method=f.get("method", "GET"),
                            proof_req=f.get("proof_req"),
                            proof_resp=f.get("proof_resp"),
                            confidence=f.get("confidence", 70),
                            remediation=f.get("remediation")
                        )

                        # Log finding
                        self.log.finding(f["vuln_type"], f["severity"],
                                        f["endpoint"], f.get("description", "")[:100])

                        # Verify finding
                        finding_dict = {**f, "id": fid}
                        verified = await self.verifier.verify(finding_dict)

                        # Generate PoC
                        poc_code = self.brain.generate_poc(finding_dict)
                        poc_path = f"{self.config.get('output_dir', 'results')}/poc/finding_{fid}_{f['vuln_type']}.py"
                        os.makedirs(os.path.dirname(poc_path), exist_ok=True)
                        with open(poc_path, "w") as pf:
                            pf.write(poc_code)

                return result.to_dict() if result else {}

            except Exception as e:
                self.log.error(f"Engine {engine_name} error: {e}")
                import traceback
                self.log.debug(traceback.format_exc())
                return {"error": str(e)}

        return None
