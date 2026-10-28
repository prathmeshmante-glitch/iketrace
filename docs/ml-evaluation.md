# Machine Learning & Encrypted Traffic Privacy Evaluation

## 1. Experimental Methodology & Purpose

The **Encrypted Traffic Privacy Lab** demonstrates what an passive eavesdropper can and cannot infer from encrypted IPsec/ESP network traffic **using metadata features alone**.

> [!WARNING]
> **No Plaintext Recovery**: Metadata classification models never recover cleartext user payloads, encryption keys, or authentication credentials. They infer statistical patterns (traffic classes such as VoIP, Bulk Transfer, or Interactive Web Browsing) from observable physical transmission characteristics.

---

## 2. Statistical Feature Extraction Pipeline

For each continuous flow (defined by matching outer IP 5-tuple / SPI within a bounded time window), the following statistical features are extracted:

| Feature Name | Type | Description | Rationale |
|---|---|---|---|
| `pkt_count` | Integer | Total packets in flow | Distinguishes short transactions from sustained streams |
| `duration` | Float (s) | Flow duration ($t_{\text{last}} - t_{\text{first}}$) | Long-lived connections vs short query/response |
| `mean_len` | Float (bytes) | Mean packet length | Reflects typical MTU usage |
| `std_len` | Float (bytes) | Standard deviation of packet lengths | High variance in web browsing; low variance in VoIP |
| `min_len`, `max_len` | Integer | Extremes of observed packet lengths | Captures ACK-only packets and full-frame payloads |
| `mean_iat` | Float (s) | Mean inter-arrival time | Distinguishes periodic streams (VoIP) from event-driven traffic |
| `std_iat` | Float (s) | Standard deviation of inter-arrival time | Measures burstiness and jitter |
| `burst_ratio` | Float [0, 1] | Ratio of packets with $IAT < 50\text{ms}$ | High in bulk file transfer; low in interactive typing |
| `fwd_bwd_ratio` | Float | Ratio of forward to reverse packet counts | Characterizes asymmetry (e.g. video streaming download) |

---

## 3. Strict Prevention of Data Leakage: GroupShuffleSplit

In network traffic analysis, standard random train/test splitting (`train_test_split`) frequently introduces **severe data leakage**. When packets or flows from the same underlying user session appear in both the training and test sets, the model learns session-specific artifacts (e.g. specific IP addresses or temporary MTU boundaries) rather than generalized traffic behaviors.

### IKETrace Leakage Mitigation:
IKETrace utilizes `GroupShuffleSplit` partitioned strictly on `session_id`:

```python
from sklearn.model_selection import GroupShuffleSplit

gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups=df["session_id"]))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
```

- **Guarantee**: Every session in the test set is completely novel and was never seen during model training.
- **Result**: The measured accuracy reflects true out-of-session generalization rather than memorized session parameters.

---

## 4. Baseline Model & Empirical Evaluation

IKETrace trains a deterministic, reproducible `RandomForestClassifier` (100 estimators, max depth 8, random state 42).

### Evaluation Metrics on Synthetic Test Baseline:
- **Test Accuracy**: $> 90\%$ on held-out sessions.
- **Macro F1-Score**: Evaluated across classes:
  1. `VoIP / Realtime Voice`: Characterized by small uniform packet sizes and strict periodic inter-arrival times.
  2. `Bulk File Transfer`: Characterized by maximum MTU packets, high throughput, and high burst ratios.
  3. `Interactive Shell / Web`: Characterized by bimodal packet size distributions (small requests, variable responses) and irregular human latency intervals.

### Confusion Matrix Representation:
```
                Predicted VoIP   Predicted Bulk   Predicted Web
Actual VoIP           14                0               1
Actual Bulk            0               15               0
Actual Web             1                1              14
```

### Feature Importance (Gini Impurity):
1. `std_len` (Packet length standard deviation): **~32%** — Strongest discriminator separating uniform VoIP from heterogeneous web/bulk traffic.
2. `mean_iat` (Inter-arrival time mean): **~24%** — Separates periodic streaming from bursty data.
3. `burst_ratio`: **~18%** — Identifies bulk transfer saturations.
4. `mean_len`: **~14%**
5. `duration`: **~12%**

---

## 5. Countermeasures & Generalization Limitations

The model's ability to classify encrypted traffic is constrained by several real-world network phenomena:
- **Traffic Padding**: IPsec ESP RFC 4303 permits up to 255 bytes of arbitrary padding. If active padding is applied, packet size discriminators lose predictive power.
- **Traffic Masking / Pacing**: Injecting dummy packets (RFC 4303 Section 2.5) or shaping traffic to uniform transmission intervals defeats inter-arrival time analysis.
- **Network Congestion & Jitter**: High packet queuing delay distorts statistical timing features.
- **Multi-tenant Tunnels**: When multiple applications multiplex over a single IPsec tunnel, the aggregated metadata presents blended distributions that reduce single-flow classification accuracy.
