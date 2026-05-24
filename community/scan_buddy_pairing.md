# WPSecScan Scan-Buddy program — design

Round-64 #131 — peer-pairing programme for security review.

## Concept

Pair up volunteers who each commit to:
- Scan the partner's WordPress site monthly
- Walk through the report together (Zoom / Discord call)
- File responsible-disclosure issues if anything critical surfaces

Both sides get a second opinion on their security posture. New
WPSecScan users get hands-on mentorship from someone who knows the
tool.

## Match algorithm

Bucket on:
- Time zone (within ±4h)
- Experience level (newbie / intermediate / expert)
- WP install type (single-site / multisite / WooCommerce / headless)
- Language

Match within bucket; if no match, fall back to "anyone available".

## Pair lifecycle

1. Sign up at `/community/scan-buddy` (TBD)
2. Wait for a match (auto, max 7 days, else manual)
3. Both parties get an intro email with the other's signup details
4. Schedule a kickoff call within 14 days
5. Monthly check-ins
6. Either party can dissolve the pairing (no friction)

## Why this matters

- Real-world security review is rare for solo WP admins
- Even just narrating findings to another human catches things a
  text-only report misses
- Builds the community around the tool

## Out of scope

- Paid coaches (different program if there's demand)
- Anonymous pairing (defeats the purpose — both sides need to
  see + verify the other's site)
- Tooling beyond a sign-up form + email matcher (run as a community
  not a product)

## Ground rules

- No live exploit testing without written consent from BOTH parties'
  legal/compliance contacts
- No data exfiltration (full or partial) even in jest
- All findings stay between the pair until publication

## Sign-up template

```
Name:
GitHub handle:
Time zone:
Experience: newbie / intermediate / expert
Site type: single / multi / woocommerce / headless
Language(s):
Why I want a buddy:
What I can offer:
```
