# OBS Recording Filename Analysis

## Filename Conventions

| OBS Feature | Filename Example | Timestamp Meaning |
|-------------|------------------|-------------------|
| **Record** | `2022-07-04 20-55-56.mkv` | Recording **START** time |
| **Replay Buffer** | `Replay 2022-07-14 01-04-59.mkv` | Recording **END** time |
| **Screenshot** | `Screenshot 2022-11-28 14-30-52.png` | Capture time |

**Timezone:** System's local time at recording (UK: BST in summer, GMT in winter)

**Note:** Replay Buffer files may show 1-2 minute discrepancy for longer captures due to disk write time.

---

## Accuracy Check Formula

```
Expected:  Filename_Time + Duration = LastWriteTime
Accuracy:  |Expected - Actual| should be < 5 seconds
```

**Typical results:** 90%+ accurate within 5 seconds, ~3s average offset.

---

## Quick Start

```bash
python obs_filename_analyzer.py "C:\Path\To\Videos"
```

Generates `obs_filename_report.txt` in the folder.

---

## Renaming Replay Files to Match Standard Convention

To convert Replay files (END time) to standard (START time):

```
New filename = Original timestamp - Duration
```

No timezone adjustment needed (both use system local time).

---

## Troubleshooting

| Issue | Cause |
|-------|-------|
| ~0s duration for long video | Corrupted LastWriteTime metadata |
| 1-hour discrepancy | DST boundary crossed, or wrong system timezone |
| Missing duration | Corrupted file or special characters in filename |

---

## Requirements

- Python 3.6+
- Windows (uses Shell for duration extraction)
