# Terms of Service

_Last updated: November 4, 2026_

These Terms of Service ("Terms") govern your use of the anti-scam Discord bot
(the "Bot") operated by the maintainers of the
[anti-scam project](https://github.com/Amirust/anti-scam) ("we", "us"). By
adding the Bot to a Discord server or interacting with it, you agree to these
Terms. If you do not agree, do not use the Bot.

The Bot's source code is public. If you run your own instance, you are its
operator: these Terms do not cover your instance, and you are responsible for
how you run it and for your own terms toward your users.

## 1. What the Bot does

The Bot detects known scam images (fake giveaways, casino spam and similar)
posted in Discord servers, typically by compromised accounts. When an image
matches its dataset of known scam images, the Bot may automatically ban the
sender, delete their recent messages, send them a direct message explaining
the ban, and post a report to the server's admin channel. Weaker matches are
reported to moderators for manual review.

The Bot is a moderation aid, not a guarantee. It can miss scam images and,
rarely, flag legitimate ones.

## 2. Eligibility

You must comply with the [Discord Terms of Service](https://discord.com/terms)
and [Community Guidelines](https://discord.com/guidelines), including Discord's
minimum age requirements, to use the Bot.

## 3. Server administrators

If you add the Bot to a server, you:

- confirm you have the authority to do so on behalf of that server;
- understand that the Bot takes automatic actions (bans and message deletion)
  in your server, and that you are responsible for configuring its permissions
  and admin channel appropriately;
- are responsible for informing your members, where required, that automated
  moderation is in place;
- are responsible for reviewing reports and reversing incorrect actions (for
  example, unbanning a user banned by mistake).

## 4. Acceptable use

You agree not to:

- use the Bot in violation of Discord's Terms of Service or any applicable law;
- attempt to disrupt, overload, reverse-engineer for abuse, or gain
  unauthorized access to the Bot, its infrastructure or its API;
- deliberately submit false reports or misuse moderation tools (such as
  "Add to dataset" or labeling buttons) to get legitimate content flagged;
- use the Bot or its HTTP API to harass, target or surveil individuals;
- share, sell or misuse API tokens issued to you.

## 5. HTTP API

Access to the Bot's HTTP API, where offered, is granted at our discretion
through individually issued tokens. Tokens are personal to the recipient,
may expire, and may be revoked at any time. Submissions are rate-limited and
may be rejected under load.

## 6. Moderator contributions

When moderators add images to the dataset or label reports, they grant us
permission to store and use the derived data (image fingerprints, embeddings
and, in some cases, a copy of the image) to improve scam detection. Do not add
images you are not permitted to share for this purpose.

## 7. Availability and changes

The Bot is provided free of charge. We may change, suspend or discontinue the
Bot or any feature at any time, without notice. We may stop serving any server
or user that violates these Terms.

## 8. Disclaimer of warranties

The Bot is provided "as is" and "as available", without warranties of any
kind, express or implied, including fitness for a particular purpose,
accuracy, or uninterrupted operation. Detection is probabilistic: false
positives and false negatives can happen.

## 9. Limitation of liability

To the maximum extent permitted by law, we are not liable for any indirect,
incidental, special or consequential damages, or for any loss of data,
access, members or reputation, arising from your use of, or inability to use,
the Bot — including actions taken by the Bot based on incorrect matches.

## 10. Open-source license

These Terms govern the use of the hosted Bot. Use, modification and
distribution of the source code are governed separately, by the license terms
published in the project's repository, if any. These Terms grant no
additional rights to the code.

## 11. Privacy

How the Bot handles data is described in the
[Privacy Policy](privacy-policy.md).

## 12. Changes to these Terms

We may update these Terms from time to time. The "Last updated" date above
reflects the latest version. Continued use of the Bot after changes take
effect means you accept the updated Terms.

## 13. Contact

Questions about these Terms can be raised through the project's
[GitHub issues](https://github.com/Amirust/anti-scam/issues).
