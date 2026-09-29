# -*- coding: utf-8 -*-
import json, itertools
from pathlib import Path

D = json.load(open(Path(__file__).resolve().parent / "full_comparison_data.json", encoding='utf-8'))
ps = D['per_sample']

print('=== chat/flash 在 [放行 vs 拦截] 级别分裂 (vote_single_veto 候选) ===')
n_s1 = 0
for vol, items in ps.items():
    for s in items:
        dc, df = s['ds_chat_bucket'], s['ds_flash_bucket']
        if (dc == 'allow') != (df == 'allow'):
            n_s1 += 1
            print(f"[{vol}] {s['id']} exp={s['expected']} flow={s['flow_bucket']} chat={dc} flash={df} "
                  f"hyb={s['hybrid_l132_bucket']} path={s['hybrid_l132_meta'].get('path')}")
print(f'放行vs拦截分裂样本数: {n_s1}\n')

print('=== flow=review 且单模型拦截 (potential single veto) ===')
n_s2 = 0
for vol, items in ps.items():
    for s in items:
        if s['flow_bucket'] == 'review':
            dc, df = s['ds_chat_bucket'], s['ds_flash_bucket']
            flag = 'SINGLE_VETO' if (dc == 'allow') != (df == 'allow') else ('BOTH_ALLOW' if dc == df == 'allow' else 'BOTH_FLAG')
            n_s2 += 1
            print(f"[{vol}] {s['id']} exp={s['expected']} chat={dc} flash={df} hyb={s['hybrid_l132_bucket']} "
                  f"path={s['hybrid_l132_meta'].get('path')} [{flag}]")
print(f'flow=review 样本数: {n_s2}\n')

print('=== 所有 fp/误拦（marked 或 hyb!=expected）样本，检查潜在 allow 误放风险 ===')
for vol, items in ps.items():
    for s in items:
        if s['hybrid_l132_bucket'] != s['expected']:
            print(f"[{vol}] {s['id']} exp={s['expected']} hyb={s['hybrid_l132_bucket']} "
                  f"flow={s['flow_bucket']} chat={s['ds_chat_bucket']} flash={s['ds_flash_bucket']} "
                  f"path={s['hybrid_l132_meta'].get('path')} | {s['text'][:60]}")