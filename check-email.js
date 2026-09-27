/**
 * check-email.js — checks the sign-up email settings in .env.
 *
 *   npm run check-email                      check the settings (and the Gmail login)
 *   npm run check-email -- you@example.com   also send one test email there
 *
 * Nothing secret is printed: keys and passwords are only described by their
 * length and shape.
 */
const config = require("./config");
const mailer = require("./mailer");

const problems = [];
const ok = (msg) => console.log("  OK    " + msg);
const bad = (msg) => { problems.push(msg); console.log("  FIX   " + msg); };
const EMAIL_RE = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]{2,}$/;

async function main() {
  const to = process.argv[2];
  console.log(`\nEmail service: ${mailer.providerLabel()}\n`);

  if (config.EMAIL_PROVIDER === "gmail") {
    const u = config.GMAIL_USER, p = config.GMAIL_APP_PASSWORD;
    if (!u) bad("GMAIL_USER is empty. Put your Gmail address there.");
    else if (!EMAIL_RE.test(u)) bad("GMAIL_USER doesn't look like an email address.");
    else if (!/@(gmail|googlemail)\.com$/i.test(u)) console.log("  NOTE  GMAIL_USER isn't an @gmail.com address. That only works for a Google Workspace account that allows App Passwords.");
    else ok("GMAIL_USER is a Gmail address.");
    if (!p) bad("GMAIL_APP_PASSWORD is empty. Create one at https://myaccount.google.com/apppasswords");
    else if (p.length !== 16 || !/^[a-z]+$/i.test(p)) bad(`GMAIL_APP_PASSWORD is ${p.length} characters; a Google App Password is 16 letters. Don't use your normal Gmail password.`);
    else ok("GMAIL_APP_PASSWORD has the shape of an App Password (16 letters).");
    if (!problems.length) {
      process.stdout.write("  ...   logging in to smtp.gmail.com (nothing is sent) ... ");
      const r = await mailer.verifyGmailLogin();
      console.log(r.ok ? "accepted." : "refused.");
      if (r.ok) ok("Gmail accepted the login.");
      else bad(r.error);
    }
  } else if (config.EMAIL_PROVIDER === "resend") {
    const k = config.EMAIL_API_KEY, f = config.EMAIL_FROM;
    if (!k) bad("EMAIL_API_KEY is empty. Create a key in Resend > API Keys.");
    else if (/^xkeysib-/.test(k)) bad("EMAIL_API_KEY is a Brevo key. Brevo is no longer used; paste your Resend key (re_...).");
    else if (!/^re_[A-Za-z0-9_]{10,}$/.test(k)) bad("EMAIL_API_KEY doesn't look like a Resend key (they start with re_).");
    else ok("EMAIL_API_KEY has the shape of a Resend key.");
    if (!f) bad("EMAIL_FROM is empty. Use an address on your verified domain (or onboarding@resend.dev to test).");
    else if (!EMAIL_RE.test(f)) bad("EMAIL_FROM must be just the address, e.g. no-reply@yourdomain.com (the name goes in EMAIL_FROM_NAME).");
    else if (/@resend\.dev$/i.test(f)) console.log("  NOTE  EMAIL_FROM is @resend.dev: Resend will only deliver to your own Resend login email until you verify a domain.");
    else if (/@(gmail|yahoo|outlook|hotmail|live|icloud)\./i.test(f)) bad("EMAIL_FROM is a free-mail address. Resend can only send from a domain you have verified in Resend.");
    else ok(`EMAIL_FROM is on ${f.split("@")[1]} — that domain must show as Verified in Resend > Domains.`);
    if (!problems.length && !to) console.log("  NOTE  Resend can't be checked without sending. Add your email to the command to send a test.");
  } else {
    bad("No service chosen. Set EMAIL_PROVIDER=gmail (or resend) and fill in its settings — see .env.example.");
  }

  if (!problems.length && to) {
    if (!EMAIL_RE.test(to)) { bad(`"${to}" isn't an email address.`); }
    else {
      process.stdout.write(`  ...   sending a test email to ${to} ... `);
      const r = await mailer.sendTestEmail(to);
      console.log(r.ok ? "sent." : "failed (reason above).");
      if (r.ok) ok("Test email sent. Check that inbox, and the spam folder.");
      else problems.push("send failed");
    }
  }

  console.log(problems.length ? "\nNot ready yet — fix the lines marked FIX, then run this again.\n"
                              : "\nEmail settings look right. Restart the backend so it picks them up.\n");
  process.exit(problems.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
