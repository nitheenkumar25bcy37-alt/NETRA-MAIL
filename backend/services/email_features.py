"""Shared readable-text input for deployed inference and probability calibration."""
def email_feature_text(parsed):
    metadata=parsed.get("metadata") or {};body=parsed.get("body") or {}
    text="\n".join(str(value) for value in (metadata.get("subject",""),metadata.get("from",""),body.get("plain",""),body.get("visible_text","")))
    image_text="\n".join(str(item.get("image_analysis",{}).get("ocr_text","")) for item in parsed.get("attachments",[]))[:20000]
    return text+"\n"+image_text if image_text else text
