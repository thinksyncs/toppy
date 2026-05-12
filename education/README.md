# Toppy Education

This directory contains educational materials for understanding Toppy, QUIC, HTTP/3, and CONNECT-UDP.

## Available Resources

- **quiz_template_skeleton.html** - An interactive bilingual (EN/JP) quiz covering Toppy fundamentals, QUIC, HTTP/3, CONNECT-UDP, and architecture
- **quiz.css** - Styles for the quiz with light/dark theme support
- **brand-mark.svg** - Local brand/fav icon used by the quiz page
- **index.html** - Redirect entry point for the deployed Pages root

## GitHub Pages Deployment

These HTML files are automatically deployed to GitHub Pages when changes are pushed to the `main` branch.

Access the quiz at: `https://thinksyncs.github.io/toppy/quiz_template_skeleton.html`

The Pages workflow publishes the contents of this directory as the site root, so page links should be relative to this directory.

## Local Development

To test the quiz locally:

1. Open `quiz_template_skeleton.html` in your web browser
2. The quiz works entirely client-side with no build step required

## Requirements

The GitHub Pages deployment is configured in `.github/workflows/deploy-pages.yml` and requires:

- GitHub Pages enabled in repository settings
- Pages configured to deploy from GitHub Actions (not branch)
- Workflow permissions set to allow deployments

## Setup GitHub Pages

To enable GitHub Pages for this repository:

1. Go to repository Settings → Pages
2. Under "Build and deployment":
   - Source: Select "GitHub Actions"
3. The workflow will automatically deploy on push to `main` branch or manual trigger
