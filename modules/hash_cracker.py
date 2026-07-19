import hashlib
from colorama import Fore, init

init(autoreset=True)

class HashCracker:
    def __init__(self, wordlist_path="/usr/share/wordlists/rockyou.txt"):
        self.wordlist_path = wordlist_path

    def crack_md5(self, target_hash, max_attempts=None):
        target_hash = target_hash.strip().lower()

        try:
            with open(self.wordlist_path, "r", encoding="latin-1") as f:
                for i, line in enumerate(f):
                    if max_attempts and i >= max_attempts:
                        break

                    word = line.strip()
                    if not word:
                        continue

                    candidate_hash = hashlib.md5(word.encode()).hexdigest()

                    if candidate_hash == target_hash:
                        return word

        except FileNotFoundError:
            print(f"{Fore.RED}[-] Wordlist not found at {self.wordlist_path}")
            return None

        return None

    def crack_extracted_credentials(self, extracted_string):
        print(f"\n{Fore.CYAN}{'='*55}")
        print(f"{Fore.CYAN}   HASH CRACKING - {self.wordlist_path.split('/')[-1]}")
        print(f"{Fore.CYAN}{'='*55}\n")

        entries = extracted_string.split("|")
        results = []

        for entry in entries:
            entry = entry.strip()
            if ":" not in entry:
                continue

            username, hash_value = entry.split(":", 1)
            hash_value = hash_value.strip()

            print(f"{Fore.BLUE}[*] Cracking hash for '{username}'...")

            plaintext = self.crack_md5(hash_value)

            if plaintext:
                print(f"{Fore.RED}[!] CRACKED: {username} : {plaintext}")
                results.append({
                    "username": username,
                    "hash": hash_value,
                    "cracked": True,
                    "plaintext": plaintext
                })
            else:
                print(f"{Fore.YELLOW}[?] Could not crack: {username} (not in wordlist)")
                results.append({
                    "username": username,
                    "hash": hash_value,
                    "cracked": False,
                    "plaintext": None
                })

        cracked_count = sum(1 for r in results if r["cracked"])
        print(f"\n{Fore.CYAN}[*] Cracked {cracked_count}/{len(results)} passwords")

        return results
