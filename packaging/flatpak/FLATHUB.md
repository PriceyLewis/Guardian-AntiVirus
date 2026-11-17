# Submitting Guardian to Flathub

Flathub is the main Flatpak app store. Once Guardian is there, GNOME Software,
KDE Discover and `flatpak update` install and update it like any other app.
Submitting is done by the app's owner through a pull request to Flathub, and a
Flathub reviewer checks it, so these are the steps to follow rather than
something CI can do.

## What is already in place

- `io.github.priceylewis.Guardian.yml` builds without network access, and every
  source is pinned by checksum or commit.
- The desktop entry passes `desktop-file-validate` and the metainfo passes
  `appstreamcli validate`.
- `flathub.json` limits builds to x86_64: the pinned Python wheels are x86_64
  only. Adding aarch64 means adding aarch64 wheels with `only-arches`.

## Steps

1. Tag a release so the manifest can point at it (for example `v1.2.0`).
2. Fork <https://github.com/flathub/flathub> and create a branch from `new-pr`.
3. Copy `io.github.priceylewis.Guardian.yml` and `flathub.json` into it.
4. In the copied manifest, replace the `guardian` module's `type: dir` source
   with the release:

   ```yaml
       sources:
         - type: git
           url: https://github.com/PriceyLewis/Guardian-AntiVirus.git
           tag: v1.2.0
           commit: <the commit the tag points to>
   ```

5. Run the linter and fix anything it reports:

   ```sh
   flatpak run --command=flatpak-builder-lint org.flatpak.Builder manifest io.github.priceylewis.Guardian.yml
   ```

6. Open the pull request against `new-pr`, titled `Add io.github.priceylewis.Guardian`.
   Expect questions about these permissions, and the reasons to give:
   - `--filesystem=home`, `/media`, `/run/media`, `/mnt`: a virus scanner must read
     the files it scans and monitors, including removable drives.
   - `--share=network`: virus definitions, threat lists and VirusTotal lookups.
   - `--filesystem=xdg-config/autostart:create`: the "Start at login" setting.
7. Flathub verifies that you control `io.github.priceylewis` by checking the
   GitHub account `PriceyLewis`; follow the instructions the reviewers give.

After acceptance, Flathub builds each new release from a pull request to the
`flathub/io.github.priceylewis.Guardian` repository it creates for you.
