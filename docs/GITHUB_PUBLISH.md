# Publish from the OpsPilot VM

The target repository is:

```text
https://github.com/Suryavarma333/opspilot-proj
```

Run the following from the GitHub-ready `opspilot-proj` directory:

```bash
git init
git branch -M main
git config user.name "Suryavarma"
git config user.email "YOUR_GITHUB_NOREPLY_EMAIL"

git add .
git status --short
git diff --cached --check
git commit -m "feat: publish OpsPilot NOC automation PoC"

git remote add origin https://github.com/Suryavarma333/opspilot-proj.git
git push -u origin main
```

For HTTPS, GitHub requires a personal access token instead of an account
password. Enter it only at Git's hidden password prompt; never place it in the
remote URL, a script, shell history, a screenshot, or this repository.

Before `git commit`, confirm that the staged file list contains no `.env`,
SQLite database, token, webhook, private key, internal hostname, or live roster
file.
