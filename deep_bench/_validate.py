# -*- coding: utf-8 -*-
import json, os
D = os.path.dirname(os.path.abspath(__file__))
for f in ["full_data_all.json", "toxicchat_results_full.json", "real_full100_results.json",
          "adv_full50_results.json", "pinject_results_scored.json"]:
    p = os.path.join(D, f)
    json.load(open(p, encoding="utf-8"))
    print("OK ", f, os.path.getsize(p))
print("data OK")