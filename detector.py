"""
QR-in-chat phishing detection lab.

Real scenario this models: a scammer messaged a seller (through eBay's own
buyer/seller chat) an image containing a QR code instead of plain text. A
text-pattern message filter that scans message bodies for suspicious
keywords/URLs never sees the payload, because the payload isn't text - it's
pixels. This script shows the other half: decoding the image and running the
URL it contains through basic reputation heuristics, which is the step a
text-only filter skips entirely.

Two parts:
  1. generate_sample_qr() - builds a QR image carrying a lookalike/off-platform
     URL, standing in for the attacker's image attachment.
  2. scan_image() - decodes it and scores the embedded URL against a small set
     of heuristics a real moderation pipeline could run inline.
"""

import cv2
import qrcode
import numpy as np
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}
PLATFORM_DOMAIN = "ebay.com"


def generate_sample_qr(url: str, path: str = "sample_payload.png") -> str:
    img = qrcode.make(url)
    img.save(path)
    return path


def decode_qr(path: str) -> str | None:
    img = cv2.imread(path)
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    return data or None


def score_url(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    flags = []
    if PLATFORM_DOMAIN not in host:
        flags.append("off-platform domain: conversation claims to be a marketplace transaction, link does not resolve to the marketplace's own domain")
    if host in URL_SHORTENERS:
        flags.append("known URL shortener: destination is hidden behind a redirect, can't be inspected before clicking")
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"low-cost/high-abuse TLD (.{tld}): cheap to register in bulk, common in short-lived phishing campaigns")
    if parsed.scheme != "https":
        flags.append("not HTTPS: no transport encryption/certificate check on the destination")

    return {
        "url": url,
        "host": host,
        "risk_flags": flags,
        "risk_level": "high" if flags else "low",
    }


def scan_image(path: str) -> dict:
    url = decode_qr(path)
    if url is None:
        return {"decoded": False, "reason": "no QR code found in image"}
    result = score_url(url)
    result["decoded"] = True
    return result


if __name__ == "__main__":
    # Stand-in for the attacker's message image. Mirrors the real shape:
    # an off-platform, shortener-style redirect instead of eBay's own checkout.
    sample_url = "https://bit.ly/ebay-release-payment-x92"
    path = generate_sample_qr(sample_url)
    result = scan_image(path)

    print(f"Decoded payload from image: {result.get('url')}")
    print(f"Risk level: {result['risk_level']}")
    for flag in result["risk_flags"]:
        print(f"  - {flag}")
