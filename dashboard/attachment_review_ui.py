"""Consent dialog and plain-language supplemental PDF findings."""
import streamlit as st


@st.dialog("Unlock a PDF for a temporary scan")
def unlock_dialog(client, email_id, digest, filename):
    unlock_form(client, email_id, digest, filename)


def unlock_form(client, email_id, digest, filename):
    st.write(filename)
    st.write("Optional: enter this document's password, not your Gmail or banking login password. Skip if you do not want to share it.")
    st.info("Your password is sent to the NETRA server for this scan. NETRA does not save it or the extracted document text. The original encrypted file and the scan findings remain in the investigation. Only the first five pages are inspected.")
    with st.form("pdf_unlock_form", clear_on_submit=True):
        password = st.text_input("Document password", type="password", max_chars=256)
        consent = st.checkbox("I agree to send this password and inspect the selected PDF.")
        submitted = st.form_submit_button("Unlock and analyse")
    if submitted:
        if not consent:
            st.warning("Select the consent box to scan, or choose Skip.")
        else:
            try:
                with st.spinner("Unlocking and checking the document…"):
                    client.unlock_pdf(email_id, digest, password)
                password = None
                st.rerun()
            except Exception:
                password = None
                st.error("Scan unavailable. Check your dashboard access and original-email availability, then retry. No safety conclusion was made.")
    if st.button("Skip — leave contents unverified"):
        st.rerun()


def render_reviews(reviews):
    if not reviews:
        return
    st.subheader("Optional PDF content reviews")
    st.caption("These are additional findings. The original email score above is preserved; a low email score does not override a suspicious attachment review.")
    for review in reviews:
        title = review.get("status", "not_inspected").replace("_", " ").capitalize()
        with st.expander(title + " | " + review.get("created_at", ""), expanded=True):
            st.code("Attachment SHA-256: " + review["attachment_sha256"], language=None)
            if review.get("status") == "suspicious":
                st.error(review["summary"])
            else:
                st.info(review["summary"])
            if review.get("error_code"):
                st.caption("Scanner status: " + review["error_code"].replace("_", " "))
            for warning in review.get("warnings", []):
                st.warning(warning)
            for page in review.get("pages", []):
                st.write("**Page " + str(page["page"]) + "**")
                st.write(" · ".join(name.upper() + ": " + status for name, status in page["checks"].items()))
                for warning in page["warnings"]:
                    st.warning(warning)
                if page.get("ml"):
                    st.caption("AI text prediction: " + str(page["ml"].get("classification", "Unknown")) + ". Supporting evidence only; this is not a probability that the attachment is safe.")
                for link in page["links"]:
                    st.code(link["host"], language=None)
                    st.write("Static URL risk: " + str(link["risk_score"]) + "/100")
                    for reason in link["reasons"]:
                        st.write(reason)
                st.caption("QR targets decoded: " + str(page["qr_count"]))
                for note in page["limitations"]:
                    st.caption(note)
            for note in review.get("limitations", []):
                st.caption(note)
