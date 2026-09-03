import Link from "next/link";

export default function LegalFooter() {
  return (
    <footer className="legal-footer">
      <span>© {new Date().getUTCFullYear()} CYPHERYN</span>
      <nav aria-label="Legal navigation">
        <Link href="/terms">Terms</Link>
        <Link href="/responsible-use">Responsible Use</Link>
        <Link href="/privacy">Privacy</Link>
        <Link href="/security">Security</Link>
        <a href="https://github.com/JedidiahBowlding/CYPHERYN/issues" target="_blank" rel="noreferrer">Contact</a>
      </nav>
    </footer>
  );
}
