"""
agent_loop.py — Autonomous AI agent loop
FIXES:
- BUG3: Node always marked tested even when engine is unknown
- BUG5: Debug logs suppressed (DNS errors not shown unless --verbose)
- BUG10: no_finding_streak only increments on real failures, not skips
"""
import asyncio
import json
import os
import time
from datetime import datetime
from typing import Dict

from core.ai_brain import AIBrain, ContextBuilder
from core.chain_detector import ChainDetector, FindingVerifier
from core.logger import Logger
from core.database import Database
from protocols.http_client import HTTPClient
from engines.engines import get_engine, ENGINE_REGISTRY


SYSTEM_PROMPT = """You are an autonomous penetration testing AI agent working on an authorized target.
Return ONLY valid JSON. No text outside JSON.

Priority: AUTH(10) > PAYMENT(10) > ADMIN(9) > GRAPHQL(8) > PROFILE(7) > FILE(7) > API(6) > NORMAL(3)
Never repeat an already-executed action.
When all high-priority endpoints tested, return {"action":"done"}.

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
    def __init__(self, config, db, http, rules, logger):
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
        self.MAX_STREAK = 40

    async def run(self) -> Dict:
        self.log.phase("AGENT LOOP")

        while True:
            self.iterations += 1

            # Stop conditions
            if self.iterations > self.max_iterations:
                self.log.warn(f"Max iterations ({self.max_iterations}) reached")
                break
            if time.time() - self.start_time > self.max_time:
                self.log.warn("Max scan time reached")
                break
            if self.no_finding_streak > self.MAX_STREAK:
                self.log.info(f"No new findings in {self.MAX_STREAK} actions — finishing")
                break

            untested = self.db.get_untested_nodes(limit=5)
            if not untested:
                self.log.info("All endpoints tested")
                break

            # Build trimmed context
            ctx = ContextBuilder.build(self.db, self.rules)

            # AI Decision (Ollama → Groq → rule-based)
            t0 = time.time()
            decision = self.brain.decide(ctx, SYSTEM_PROMPT)
            dt = int((time.time()-t0)*1000)

            action     = decision.get("action","done")
            engine_name= decision.get("engine","")
            params     = decision.get("params",{})
            reason     = decision.get("reason","")
            confidence = decision.get("confidence",70)
            model      = decision.get("_model","rule-based")

            self.log.ai_decision(action, engine_name, reason, confidence)

            # Log to DB
            self.db.log_action(action=action, engine=engine_name, params=params,
                               reason=reason, ai_model=model,
                               confidence=confidence, duration_ms=dt)

            if action == "done":
                self.log.info("AI decided: scan complete")
                break

            # FIX BUG3: Always mark node tested, even if engine unknown
            endpoint_url = params.get("endpoint") or params.get("url","")

            # Skip duplicate actions — but don't count as no_finding
            if self.db.action_exists(action, engine_name, params):
                self.log.debug(f"Duplicate action skipped: {engine_name}")
                # Mark node tested so we don't loop forever on same node
                self._mark_tested(endpoint_url)
                continue

            # Validate engine exists
            if action in ["run_engine","test_endpoint"] and engine_name not in ENGINE_REGISTRY:
                self.log.warn(f"Unknown engine '{engine_name}' — marking tested, continuing")
                self._mark_tested(endpoint_url)
                # FIX BUG10: don't count unknown engine as "no finding"
                continue

            # Execute
            findings_before = len(self.db.get_findings())
            result = await self._execute(action, engine_name, params)
            findings_after = len(self.db.get_findings())

            # Mark node tested ALWAYS after execution
            self._mark_tested(endpoint_url)

            # Chain detection on new findings
            if findings_after > findings_before:
                self.no_finding_streak = 0
                self.chain_detector.detect()
            else:
                # FIX BUG10: only increment streak on actual engine runs, not skips
                self.no_finding_streak += 1

            # Progress every 10 iterations
            if self.iterations % 10 == 0:
                self.db.checkpoint()
                s = self.db.get_stats()
                self.log.stats({
                    "Loop": self.iterations,
                    "Tested": f"{s['tested_nodes']}/{s['total_nodes']}",
                    "Findings": f"{s['verified_findings']}v/{s['total_findings']}t",
                    "Critical/High": f"{s['critical']}/{s['high']}",
                    "Chains": s['chains'],
                    "Model": model,
                })

            await asyncio.sleep(0.3)

        # Final
        stats = self.db.get_stats()
        self.log.stats({
            "COMPLETE": "═"*20,
            "Iterations": self.iterations,
            "Endpoints": f"{stats['tested_nodes']}/{stats['total_nodes']}",
            "Critical": stats['critical'],
            "High": stats['high'],
            "Chains": stats['chains'],
            "Time": f"{int(time.time()-self.start_time)}s",
        })
        return {"status":"complete","stats":stats}

    def _mark_tested(self, url):
        """Mark a node as tested by URL"""
        if not url:
            return
        try:
            c = self.db.conn.cursor()
            c.execute("UPDATE nodes SET tested=1 WHERE url=?", (url,))
            self.db.conn.commit()
        except:
            pass

    async def _execute(self, action, engine_name, params) -> dict:
        engine = get_engine(engine_name, self.http, self.db, self.rules, self.log)
        if not engine:
            return {}
        try:
            result = await engine.run(params)
            if result and result.findings:
                output_dir = self.config.get("output_dir","results")
                for f in result.findings:
                    fid = self.db.add_finding(
                        vuln_type=f["vuln_type"], severity=f["severity"],
                        endpoint=f["endpoint"], description=f["description"],
                        param=f.get("param"), method=f.get("method","GET"),
                        proof_req=f.get("proof_req"), proof_resp=f.get("proof_resp"),
                        confidence=f.get("confidence",70),
                        remediation=f.get("remediation")
                    )
                    self.log.finding(f["vuln_type"], f["severity"],
                                     f["endpoint"], f.get("description","")[:80])
                    # Verify
                    verified = await self.verifier.verify({**f,"id":fid})
                    # PoC
                    poc = self.brain.generate_poc({**f,"id":fid})
                    poc_path = os.path.join(output_dir,"poc",
                                            f"finding_{fid}_{f['vuln_type']}.py")
                    os.makedirs(os.path.dirname(poc_path), exist_ok=True)
                    try:
                        with open(poc_path,"w") as pf:
                            pf.write(poc)
                    except:
                        pass
            return result.to_dict() if result else {}
        except Exception as e:
            self.log.error(f"Engine {engine_name} error: {e}")
            return {"error": str(e)}

