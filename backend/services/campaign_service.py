from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from backend.campaign_correlator import CampaignCorrelator


class CampaignService:
    def __init__(self, db: Any):
        self.db = db

    def correlate(self, email_id: str) -> Dict[str, Any]:
        source = self.db.get_v2_analysis(email_id)
        if not source:
            raise KeyError("Email analysis was not found")
        candidates = self.db.list_v2_analyses_page(limit=200)["items"]
        relationships = CampaignCorrelator.correlate(email_id, source, candidates)
        saved = []
        for relationship in relationships:
            ordered = dict(relationship)
            if ordered["source_email_id"] > ordered["target_email_id"]:
                ordered["source_email_id"], ordered["target_email_id"] = ordered["target_email_id"], ordered["source_email_id"]
            if self.db.save_relationship(ordered):
                saved.append(ordered)
        all_relationships = self.db.get_relationships(email_id)
        from backend.services.investigation_graph import qualified
        records = {item["email_id"]: item for item in candidates}
        records[email_id] = source
        strong = [item for item in all_relationships if qualified(item, records)]
        campaigns = self.db.list_campaigns()
        candidate_campaigns = []
        for campaign in campaigns:
            members = set(self.db.get_campaign_emails(campaign["campaign_id"]))
            related = [item for item in strong if item.get("source_email_id") in members or item.get("target_email_id") in members]
            if related:
                candidate_campaigns.append({"campaign_id": campaign["campaign_id"], "confidence": max(item["confidence"] for item in related), "reason": self._reason(related), "requires_review": True})
        if strong and not candidate_campaigns:
            top = max(strong, key=lambda item: item["confidence"])
            label = self._label(top)
            now = datetime.now(timezone.utc).isoformat()
            campaign = self.db.create_campaign({"campaign_id": "camp_" + uuid4().hex[:12], "name": label, "description": "Automatically grouped from observed email indicators.", "status": "suspected", "confidence": top["confidence"], "analyst_confirmed": False, "created_at": now, "updated_at": now, "primary_indicators": [item["relationship_type"] for item in strong[:5]]})
            candidate_campaigns.append({"campaign_id": campaign["campaign_id"], "confidence": top["confidence"], "reason": self._reason(strong), "requires_review": True})
            member_ids = {email_id}
            for item in strong:
                member_ids.update((item["source_email_id"], item["target_email_id"]))
            for member_id in member_ids:
                self.db.add_campaign_email(campaign["campaign_id"], member_id)
        else:
            for candidate in candidate_campaigns:
                for item in strong:
                    self.db.add_campaign_email(candidate["campaign_id"], item["source_email_id"])
                    self.db.add_campaign_email(candidate["campaign_id"], item["target_email_id"])
                self.db.add_campaign_email(candidate["campaign_id"], email_id)
        return {"relationships_found": len(all_relationships), "new_relationships": len(saved), "relationships": all_relationships, "candidate_campaigns": candidate_campaigns, "requires_review": bool(candidate_campaigns)}

    @staticmethod
    def _reason(relationships: List[Dict[str, Any]]) -> str:
        labels = {item["relationship_type"].replace("shared_", "").replace("_", " ") for item in relationships}
        return "Possible campaign relationship based on " + ", ".join(sorted(labels)[:3]) + "; requires analyst confirmation."

    @staticmethod
    def _label(relationship: Dict[str, Any]) -> str:
        labels = {"shared_attachment_hash": "Shared attachment campaign", "shared_url": "Related suspicious URL campaign", "shared_reply_to": "Common Reply-To infrastructure", "shared_sender": "Shared sender campaign", "shared_impersonated_brand": "Possible impersonation campaign"}
        return labels.get(relationship["relationship_type"], "Suspected shared-indicator campaign")

    def get_relationships(self, email_id: str) -> List[Dict[str, Any]]:
        return self.db.get_relationships(email_id)

    def list_campaigns(self) -> List[Dict[str, Any]]:
        campaigns = self.db.list_campaigns()
        for campaign in campaigns:
            campaign["email_ids"] = self.db.get_campaign_emails(campaign["campaign_id"])
            campaign["email_count"] = len(campaign["email_ids"])
            campaign["relationships"] = [relationship for email_id in campaign["email_ids"] for relationship in self.db.get_relationships(email_id)]
            campaign["relationship_count"] = len({(item["source_email_id"], item["target_email_id"], item["relationship_type"]) for item in campaign["relationships"]})
        return campaigns

    def get_campaign(self, campaign_id: str) -> Dict[str, Any] | None:
        campaign = self.db.get_campaign(campaign_id)
        if campaign:
            campaign["email_ids"] = self.db.get_campaign_emails(campaign_id)
            campaign["relationships"] = [relationship for email_id in campaign["email_ids"] for relationship in self.db.get_relationships(email_id)]
            campaign["email_count"] = len(campaign["email_ids"])
            campaign["relationship_count"] = len({(item["source_email_id"], item["target_email_id"], item["relationship_type"]) for item in campaign["relationships"]})
        return campaign
