# masq-pipeline

Encrypted lookmovie2 -> TeraBox pipeline. Runs entirely in GitHub Actions.

## Setup (once)

Add these repo secrets under Settings -> Secrets and variables -> Actions:

- `TERABOX_1_COOKIE` - account 1 ndus value
- `TERABOX_2_COOKIE` - account 2 ndus value
- `TERABOX_3_COOKIE` - account 3 ndus value
- ~~`EE_TB_PASSPHRASE`~~ -> now a per-run workflow input, not a secret

Optional (only needed if you want username/password fallback):
- `TERABOX_1_USERNAME`, `TERABOX_1_PASSWORD`
- `TERABOX_2_USERNAME`, `TERABOX_2_PASSWORD`
- `TERABOX_3_USERNAME`, `TERABOX_3_PASSWORD`
- `DISCORD_WEBHOOK_URL` (notification on job end)

## Run

Actions tab -> pipeline -> Run workflow. Fill in:

- URL: lookmovie2 show/movie URL
- Mode: single | ghost | ghost-batch
- Show: short name for filename
- Season: number
- Episodes: e.g. `1` or `1-5`
- Wait: seconds to wait for player (default 25)

## Outputs

- Encrypted shards land in TeraBox accounts 1/2/3
- `uploads.csv` manifest -> job artifact
- Job log shows full capture trace

## CLI trigger

    gh workflow run pipeline.yml \
      -f url="https://www.lookmovie2.to/shows/view/..." \
      -f mode=ghost -f show=GH -f season=6 -f episodes=9


## Reconstruct workflow

Actions tab -> **reconstruct** -> Run workflow. Inputs:

- `ghost_folder`: full TeraBox path (e.g. `/_Rescue_Uploads/encrypted/Ghosts/<ghost_id>`)
- `passphrase`: the same one used at capture time
- `dest_account`: which TeraBox account receives the decrypted MP4 (1/2/3)
- `dest_dir`: remote folder for the MP4 (e.g. `/decrypted`)
- `keep_shards`: leave shards on TeraBox after reconstruct

Output: the decrypted MP4 uploaded to `dest_account:dest_dir`. Nothing touches your local machine.
