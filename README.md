# DATN-Packetra

## 1. Giới thiệu

`DATN-Packetra` là một công cụ phân tích mạng có giao diện đồ họa, được xây dựng để phục vụ học tập, nghiên cứu, trực quan hóa lưu lượng mạng và hỗ trợ phân tích hành vi an toàn thông tin. Mục tiêu của project là làm cho việc đọc file PCAP, quan sát packet, suy luận flow, xem dashboard, mô phỏng demo traffic và tích hợp AI trở nên dễ tiếp cận hơn đối với sinh viên hoặc người mới bắt đầu so với các công cụ chuyên sâu như Wireshark.

Project không chỉ dừng ở mức “mở file và xem packet”, mà còn cố gắng trả lời những câu hỏi thực tế như:

- Host nào đang giao tiếp với host nào?
- Luồng mạng nào đáng chú ý?
- Có dấu hiệu tấn công hay bất thường không?
- Nếu có, đó là loại hành vi nào?
- Kết quả AI có thể được diễn giải như thế nào ở mức flow hoặc action?

## 2. Mục tiêu project

- Xây dựng một công cụ phân tích mạng phục vụ học tập, demo và nghiên cứu an toàn thông tin.
- Cung cấp giao diện trực quan hơn cho người mới: packet list, packet details, packet bytes, dashboard, topology.
- Hỗ trợ cả phân tích packet-level và flow-level.
- Tích hợp pipeline AI để suy luận hành vi mạng từ flow features.
- Hỗ trợ demo packet/action để minh họa tình huống mạng và tình huống tấn công.
- Tạo nền tảng để mở rộng tiếp sang dashboard nâng cao, remote capture, behavioral analysis và explainable AI.

## 3. Project dùng để làm gì?

Project có thể được dùng cho các nhu cầu sau:

- Mở và đọc file `pcap` / `pcapng`.
- Quan sát packet theo thời gian, protocol, source/destination, length, info.
- Phân tích sâu packet bằng cây field chi tiết và vùng bytes/hex.
- Tách lưu lượng thành flow để phân tích ở mức phiên giao tiếp.
- Xuất flow ra CSV để phục vụ phân tích hoặc đưa vào model AI.
- Chạy AI analyst để dự đoán hành vi/tấn công từ flow.
- Xem dashboard để có góc nhìn tổng quan.
- Xem network topology để quan sát quan hệ giữa host, IP, protocol và flow lines.
- Mở demo packet theo action mẫu để phục vụ giảng dạy hoặc minh họa.
- Dùng remote capture để lấy traffic từ máy chủ từ xa.

## 4. Các chức năng chính

### 4.1. Packet Analysis

- Đọc file `pcap` và `pcapng`.
- Hiển thị danh sách packet theo cột `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`.
- Hiển thị phần packet details dạng cây để xem các field đã parse.
- Hiển thị vùng packet bytes/hex để kiểm tra dữ liệu thô.
- Hỗ trợ tô màu packet, filter, search, follow stream, apply as filter, copy, comment, mark/ignore.

### 4.2. Flow Analysis

- Gom nhiều packet thành flow bằng `core.flow_engine`.
- Mỗi flow biểu diễn một phiên hoặc một chiều/2 chiều giao tiếp theo logic extractor.
- Flow có thể chứa nhiều thuộc tính như:
  - Source IP, Destination IP
  - Source Port, Destination Port
  - Protocol
  - Start time / End time
  - Duration
  - Total forward/backward packets
  - Total forward/backward bytes
  - Flow IAT, packet length statistics, flag statistics, window size, idle/active time
- Có thể xuất flow thành CSV từ:
  - toàn bộ capture hiện tại
  - chỉ phần packet được chọn

### 4.3. AI Detection / AI Analyst

- Project có tích hợp module AI để phân tích flow và suy luận nhãn hành vi mạng.
- Kết quả AI được trình bày theo hướng:
  - tổng số flow đã phân tích
  - phân bố nhãn
  - các flow đáng nghi
  - mô tả ngắn gọn theo nhãn dự đoán
- AI analyst không phân tích trực tiếp từ từng packet đơn lẻ, mà phân tích trên flow features được trích xuất từ packet.

### 4.4. Dashboard

- Hệ dashboard cho phép xem capture dưới dạng các widget tổng quan.
- Có sẵn dashboard templates trong `data/dashboard_templates/`.
- Có thể tạo dashboard mới, import dashboard, export JSON dashboard, rename, duplicate và delete.
- Dashboard tập trung vào trực quan hóa như:
  - protocol distribution
  - endpoint activity
  - timeline analysis
  - HTTP/TLS analysis
  - DNS analysis
  - security investigation
  - topology-style overview

### 4.5. Network Topology

- Vẽ sơ đồ mạng từ capture.
- Thể hiện node, edge, protocol summary và flow lines giữa các host.
- Hữu ích để quan sát trực quan:
  - ai đang nói chuyện với ai
  - protocol nào nổi bật
  - port nào đang được sử dụng
  - có node/edge nào bất thường không

### 4.6. Demo Packet

- Có menu mở demo packet/action từ thư mục `demo/`.
- Mỗi demo đại diện cho một action hoặc tình huống mạng cụ thể.
- Mục tiêu chính:
  - minh họa hành vi mạng
  - minh họa packet/flow của một tình huống
  - tạo dữ liệu trình diễn nhanh khi giảng dạy hoặc demo project

### 4.7. Remote Capture

- Có hỗ trợ remote capture thông qua cấu hình remote interfaces.
- Về mặt code, project đã có các thành phần như:
  - `core.remote_capture.py`
  - `core.capture.RemotePacketSniffer`
  - `gui.manage_interfaces_dialog.py`
- Mục tiêu là cho phép người dùng lấy traffic từ máy từ xa thay vì chỉ capture local trên Windows.

### 4.8. Help / User Guide

- Project có bộ tài liệu HTML trong thư mục `help/`.
- Tài liệu này được mở từ menu `Help` trong ứng dụng.
- Các file hiện có gồm:
  - `help/index.html`
  - `help/user_guide.html`
  - `help/capture_workflow.html`
  - `help/capture_filter_guide.html`
  - `help/filter_reference.html`
  - `help/dashboard_guide.html`
  - `help/agent_guide.html`

## 5. Phân biệt các khái niệm quan trọng

### 5.1. Packet là gì?

Packet là đơn vị dữ liệu mạng nhỏ nhất mà công cụ đang đọc trực tiếp từ file PCAP hoặc từ capture live. Một packet thường có:

- địa chỉ nguồn
- địa chỉ đích
- protocol
- port
- payload
- timestamp

Ví dụ: một gói TCP từ `192.168.1.10:51514` đến `192.168.1.20:80`.

### 5.2. PCAP là gì?

`PCAP` / `PCAPNG` là định dạng file dùng để lưu packet capture. Đây là đầu vào gốc của project khi người dùng mở file capture.

### 5.3. Flow là gì?

Flow là một tập packet được gom lại thành một phiên giao tiếp logic. Thay vì nhìn từng packet rời rạc, flow cho phép nhìn toàn bộ một kết nối hoặc một chiều lưu lượng dưới dạng thống kê.

Ví dụ:

- nhiều packet TCP từ `192.168.1.10:51514` đến `192.168.1.20:80`
- được gom thành một flow HTTP/TCP
- từ flow này có thể tính duration, packet count, byte count, inter-arrival time, flag statistics, throughput, v.v.

### 5.4. CSV flow là gì?

CSV flow là file đầu ra sau khi packet được gom thành flow và mỗi dòng CSV đại diện cho một flow. CSV này phù hợp cho:

- hậu kiểm
- nhập vào notebook hoặc script phân tích
- đưa vào AI model để predict

### 5.5. Dataset train AI là gì?

Dataset train AI là tập dữ liệu flow đã có nhãn sẵn. Mỗi dòng là một flow và có cột `Label` để cho biết flow đó là benign hay thuộc loại tấn công nào.

### 5.6. Feature là gì?

Feature là các cột số hoặc thông tin đã được chuẩn hóa để model dùng làm đầu vào. Ví dụ:

- Flow Duration
- Total Fwd Packets
- Total Backward Packets
- Packet Length Mean
- Flow Bytes/s
- SYN Flag Count

### 5.7. Label là gì?

Label là nhãn đích của flow, ví dụ:

- `Benign`
- `DDoS`
- `PortScan`
- `Web Attack - XSS`

### 5.8. Train khác gì Predict?

- `Train`: dùng dataset đã gán nhãn để huấn luyện model.
- `Predict`: dùng flow mới chưa có nhãn để model dự đoán nhãn.

Nói ngắn gọn:

- Train cần `features + label`
- Predict chỉ có `features`, model sẽ sinh ra `label dự đoán`

## 6. Luồng hoạt động tổng thể

Workflow tổng quát của project:

1. Người dùng mở ứng dụng.
2. Người dùng chọn:
   - mở file PCAP/PCAPNG
   - capture trực tiếp
   - mở demo packet
3. Hệ thống nạp packet vào `CaptureView`.
4. Packet được parse để hiển thị ở packet list, details và bytes.
5. Khi cần phân tích flow/AI:
   - packet được chuyển qua `FlowFeatureExtractor`
   - flow features được tạo ra
   - flow có thể được xuất ra CSV
   - flow được đưa vào `PacketraModelAdapter`
   - model sinh nhãn dự đoán
6. Kết quả được hiển thị ra:
   - AI Analyst
   - CSV export summary
   - dashboard
   - topology / flow graph / behavioral summaries

## 7. AI pipeline hiện tại

## 7.1. Điều quan trọng cần biết

Trong các mô tả cũ hoặc ghi chú cũ, project từng được nhắc tới theo hướng dùng `XGBoost`. Tuy nhiên, trạng thái repo hiện tại cho thấy bộ artifact AI đang được đóng gói là **FT-Transformer TorchScript chạy trên CPU**, không phải file model XGBoost.

Điều này được xác nhận từ:

- [ai/model_info.json](D:/DATN-Packetra/ai/model_info.json)
- [gui/application.py](D:/DATN-Packetra/gui/application.py)
- [core/flow_engine/model_adapter.py](D:/DATN-Packetra/core/flow_engine/model_adapter.py)

`PacketraModelAdapter` vẫn hỗ trợ cả hai hướng:

- TorchScript (`.pt`)
- XGBoost (`.json`)

Nhưng artifact hiện đang có trong repo là TorchScript.

### 7.2. Artifact AI hiện có trong repo

Thư mục `ai/` hiện đang chứa:

- `ft_transformer_torchscript.pt`
- `standard_scaler.pkl`
- `label_encoder.pkl`
- `model_info.json`

### 7.3. Vai trò từng file AI

- `ft_transformer_torchscript.pt`
  - model đã export sang TorchScript để suy luận trực tiếp trong app
- `standard_scaler.pkl`
  - scaler dùng để chuẩn hóa feature trước khi đưa vào model
- `label_encoder.pkl`
  - ánh xạ chỉ số dự đoán sang tên nhãn
- `model_info.json`
  - mô tả metadata của model: loại model, số feature, số lớp, tên lớp, cấu hình train

### 7.4. Feature columns

Một số tài liệu cũ có nhắc tới `feature_columns.json`. Tuy nhiên repo hiện tại **không đóng gói file này trong thư mục `ai/`**. Thay vào đó:

- phần thứ tự feature đang được xác định từ danh sách cột AI trong code
- xem `AI_TRAFFIC_COLUMNS` và `_ai_model_feature_order()` trong [gui/application.py](D:/DATN-Packetra/gui/application.py)
- `model_info.json` vẫn nhắc tới `feature_columns_file`, cho thấy pipeline train/export trước đây có khả năng từng sinh file này ở môi trường train

README này vì vậy mô tả đúng trạng thái hiện tại:

- **artifact inference đang dùng:** TorchScript + scaler + label encoder + model_info
- **thứ tự feature trong app hiện tại:** lấy từ code

### 7.5. Pipeline AI trong app

Pipeline suy luận trong project hiện tại:

1. Đọc packet từ capture hoặc file PCAP.
2. Gom packet thành flow bằng `FlowFeatureExtractor`.
3. Chuyển flow thành bảng feature.
4. Chọn đúng thứ tự feature mà model yêu cầu.
5. Chuẩn hóa feature bằng `StandardScaler`.
6. Đưa vào model TorchScript.
7. Nhận index lớp dự đoán.
8. Giải mã sang tên nhãn bằng `label_encoder.pkl`.
9. Hiển thị kết quả cho người dùng dưới dạng summary và per-flow prediction.

## 8. Dataset

### 8.1. Dataset nền tảng

Project được xây dựng theo hướng flow-based và có tham chiếu rõ tới các đặc trưng kiểu CICFlowMeter. Vì vậy dataset nền tảng phù hợp nhất là các dataset flow-based như `CIC-IDS-2017` và các biến thể/merged dataset tương thích với schema CIC.

### 8.2. Điều quan trọng về dataset

Mỗi dòng CSV trong dataset kiểu CIC là **một flow**, không phải một packet.

Đây là điểm rất quan trọng:

- PCAP là packet-level
- CSV dataset train AI là flow-level

Nghĩa là project phải đi qua bước `packet -> flow -> feature table` trước khi có thể predict bằng model.

### 8.3. Nhãn hiện có trong model đóng gói

Theo [ai/model_info.json](D:/DATN-Packetra/ai/model_info.json), model hiện tại có 15 lớp:

- `ARP_Spoofing`
- `Benign`
- `Bot`
- `Brute Force Attacks`
- `DDoS`
- `DoS Hulk`
- `DrDoS_DNS`
- `DrDoS_MSSQL`
- `FTP-BruteForce`
- `Infiltration`
- `Man-in-the-middle`
- `PortScan`
- `Web Attack - Brute Force`
- `Web Attack - SQL Injection`
- `Web Attack - XSS`

### 8.4. Liên hệ với CIC-IDS-2017

Nếu bạn đang viết báo cáo hoặc giải thích học thuật, có thể nói:

- project bắt đầu từ hướng tiếp cận tương thích CIC/CICFlowMeter
- các feature và flow schema bám theo phong cách CIC
- model hiện tại được train trên một tập dữ liệu 15 lớp đã hợp nhất/chuẩn hóa từ nguồn CIC-IDS-2017 và dữ liệu bổ sung

Theo `model_info.json`, dữ liệu train tham chiếu tới:

- `final_selected_15.csv`
- `merged_static_unit_aligned_6_labels.csv`

Điều này cho thấy model hiện tại không còn là “CIC-IDS-2017 nguyên bản 1:1”, mà là một bộ train đã được chọn lớp và merge thêm dữ liệu tương thích.

## 9. Kết quả train và tài liệu train

Tài liệu train hiện có trong repo:

- [docs/full train kaggle.md](D:/DATN-Packetra/docs/full%20train%20kaggle.md)

Tuy nhiên, file này hiện giống ghi chú nội bộ hơn là báo cáo train hoàn chỉnh. Nó cho thấy:

- định hướng cân bằng lớp
- oversampling / weighting cho một số lớp hiếm
- theo dõi các lớp khó như XSS, SQL Injection, MITM, ARP spoofing, DrDoS, brute force

### 9.1. Về các chỉ số Accuracy / Macro F1

Bạn đã yêu cầu README nêu các chỉ số như:

- Validation Accuracy ~ `0.998999`
- Validation Macro F1 ~ `0.896475`
- Test Accuracy ~ `0.998971`
- Test Macro F1 ~ `0.880355`

README này có thể ghi các chỉ số đó như **kết quả train tham chiếu trong tài liệu/ghi chú nghiên cứu**, nhưng cần nói rõ:

- đây là kết quả của pipeline train trước đó
- không phải chỉ số được tự động xác thực lại từ artifact hiện đang đóng gói trong repo
- accuracy cao thường chịu ảnh hưởng bởi class imbalance
- macro F1 phản ánh rõ hơn chất lượng trên lớp hiếm

### 9.2. Cách diễn giải các chỉ số

- `Accuracy` cao không đồng nghĩa tất cả lớp đều tốt.
- Trong bài toán IDS nhiều lớp, `Macro F1` thường quan trọng hơn vì nó cân bằng các lớp hiếm.
- Nếu lớp hiếm như `Web Attack - XSS`, `Man-in-the-middle` hoặc `Bot` ít dữ liệu, model có thể vẫn đạt accuracy cao nhưng dự đoán chưa ổn định trên các lớp đó.

## 10. Ví dụ dễ hiểu cho người mới

### 10.1. Ví dụ packet

Một packet:

- Source: `192.168.1.10`
- Destination: `192.168.1.20`
- Protocol: `TCP`
- Destination Port: `80`

Điều này mới chỉ cho thấy một gói tin đơn lẻ đang đi từ máy A sang máy B.

### 10.2. Ví dụ flow

Nếu có nhiều packet liên tiếp giữa:

- `192.168.1.10:51514`
- `192.168.1.20:80`

thì hệ thống có thể gom chúng thành một flow HTTP/TCP.

Flow đó có thể được mô tả như:

- tổng 18 packet
- tổng 12 KB
- duration 1.8 giây
- tốc độ trung bình X bytes/s
- có SYN, ACK, PSH

### 10.3. Ví dụ predict benign

Nếu model dự đoán:

- `Benign`

thì cách hiểu tự nhiên là:

- lưu lượng này trông giống giao tiếp bình thường
- chưa thấy dấu hiệu rõ ràng của quét cổng, brute-force, DDoS hoặc web attack

### 10.4. Ví dụ predict PortScan

Nếu model dự đoán:

- `PortScan`

thì có thể hiểu:

- một nguồn đang thử kết nối tới nhiều cổng hoặc nhiều dịch vụ
- đây có thể là hành vi do thám bề mặt tấn công

### 10.5. Ví dụ predict DDoS

Nếu model dự đoán:

- `DDoS`

thì có thể hiểu:

- có lượng flow hoặc packet dồn dập vào một đích
- mục tiêu là gây quá tải dịch vụ

## 11. Cấu trúc thư mục project

Project gốc nằm tại:

```text
D:\DATN-Packetra
```

### 11.1. Thư mục cấp cao

- `ai/`
  - chứa artifact AI đang dùng để suy luận
  - hiện có TorchScript model, scaler, label encoder, model info
- `core/`
  - logic xử lý lõi
  - capture, filtering, parser, formatter, firewall ACL, remote capture
- `core/flow_engine/`
  - engine sinh flow và xuất CSV
  - đây chính là phần có thể xem như `PacketraFlowEngine`
- `gui/`
  - toàn bộ giao diện người dùng PySide6
- `gui/dashboard/`
  - dashboard overview, dashboard editor, query engine, visualization, repository
- `data/`
  - dashboard templates và dữ liệu dashboard người dùng
- `demo/`
  - file `pcapng` demo cho chế độ Demo Packet
- `help/`
  - tài liệu HTML mở từ menu Help
- `image/`
  - icon và tài nguyên giao diện
- `utils/`
  - parser phụ trợ, IO, system check, network utilities, compile helper
- `docs/`
  - tài liệu tham khảo, ghi chú train, tài liệu luận văn
- `.venv/`
  - môi trường ảo Python cục bộ
- `main.py`
  - entrypoint GUI chính
- `requirements.txt`
  - danh sách dependency chính

### 11.2. Một số file quan trọng

- [main.py](D:/DATN-Packetra/main.py)
  - chạy ứng dụng GUI
- [gui/application.py](D:/DATN-Packetra/gui/application.py)
  - cửa sổ ứng dụng chính, menu, toolbar, dashboard, AI analyst, statistics, demo packet
- [gui/capture_view.py](D:/DATN-Packetra/gui/capture_view.py)
  - packet list, details, bytes, load/save capture, filter, capture state
- [core/capture.py](D:/DATN-Packetra/core/capture.py)
  - packet sniffer local/remote
- [core/parser.py](D:/DATN-Packetra/core/parser.py)
  - phân tích packet và sinh record đã parse
- [core/formatters.py](D:/DATN-Packetra/core/formatters.py)
  - định dạng chi tiết packet/section/info
- [core/filtering.py](D:/DATN-Packetra/core/filtering.py)
  - display filter
- [core/flow_engine/feature_extractor.py](D:/DATN-Packetra/core/flow_engine/feature_extractor.py)
  - gom packet thành flow và tính feature
- [core/flow_engine/csv_exporter.py](D:/DATN-Packetra/core/flow_engine/csv_exporter.py)
  - xuất flow ra CSV
- [core/flow_engine/model_adapter.py](D:/DATN-Packetra/core/flow_engine/model_adapter.py)
  - adapter nạp model AI và chạy predict
- [utils/pcap_io.py](D:/DATN-Packetra/utils/pcap_io.py)
  - đọc/ghi file pcap/pcapng và metadata
- [utils/system_check.py](D:/DATN-Packetra/utils/system_check.py)
  - kiểm tra Npcap và thông tin hệ thống
- [utils/compile_project.py](D:/DATN-Packetra/utils/compile_project.py)
  - compile nhanh code project, bỏ qua `.venv`

## 12. Cài đặt môi trường

### 12.1. Yêu cầu

- Windows là môi trường được hỗ trợ tốt nhất cho local capture
- Python 3.11 là lựa chọn an toàn nhất cho bộ dependency hiện tại
- Npcap cần được cài nếu muốn live capture trên Windows

### 12.2. Tạo virtual environment

PowerShell:

```powershell
cd D:\DATN-Packetra
python -m venv .venv
.venv\Scripts\Activate.ps1
```

CMD:

```cmd
cd D:\DATN-Packetra
python -m venv .venv
.venv\Scripts\activate.bat
```

### 12.3. Cài dependency

```powershell
pip install -r requirements.txt
```

### 12.4. Dependency chính

Theo [requirements.txt](D:/DATN-Packetra/requirements.txt), project đang dùng:

- `scapy`
- `PySide6`
- `psutil`
- `lz4`
- `paramiko`
- `pywin32`
- `numpy`
- `xgboost`
- `scikit-learn`
- `joblib`
- `torch` CPU wheel

### 12.5. Npcap

Nếu chạy local capture trên Windows mà chưa có Npcap, `main.py` sẽ cảnh báo và yêu cầu cài đặt.

Trang chủ:

```text
https://npcap.com/
```

## 13. Cách chạy project

### 13.1. Chạy GUI chính

```powershell
python main.py
```

### 13.2. Kiểm tra compile code project

Để compile toàn bộ code của project mà không đụng vào `.venv`:

```powershell
python utils\compile_project.py
```

### 13.3. Chạy các luồng chính trong GUI

Sau khi mở app, bạn có thể:

1. Mở file PCAP/PCAPNG.
2. Chọn interface để capture trực tiếp.
3. Mở `Demo Packet`.
4. Xuất flow CSV từ capture hiện tại.
5. Chạy AI Analyst trên packet/flow đã chọn.
6. Mở Dashboard hoặc Network Topology.

### 13.4. Dự đoán AI

Trong trạng thái hiện tại, AI được tích hợp trực tiếp vào GUI thay vì có một CLI predictor riêng biệt rõ ràng. Các luồng dùng model chủ yếu đi qua:

- AI Analyst
- Export Flow CSV + behavioral summary

Nếu sau này bạn tách CLI riêng, README có thể mở rộng thêm phần:

```powershell
python some_predict_script.py --input flow.csv
```

### 13.5. Train model

Repo hiện tại không cung cấp một file train chuẩn hóa duy nhất kiểu `train.py` ở root. Phần train hiện được phản ánh qua:

- artifact trong `ai/`
- ghi chú trong `docs/full train kaggle.md`
- metadata trong `ai/model_info.json`

Vì vậy README mô tả train theo hướng:

- pipeline train đã tồn tại ở môi trường nghiên cứu/Kaggle
- artifact suy luận đã được export vào repo

## 14. PacketraFlowEngine và CICFlowMeter

### 14.1. PacketraFlowEngine là gì?

Trong repo hiện tại, phần tương đương `PacketraFlowEngine` chính là thư mục:

- [core/flow_engine](D:/DATN-Packetra/core/flow_engine)

Nó chịu trách nhiệm:

- tạo khóa flow
- gom packet thành flow
- tính feature
- xuất CSV
- cung cấp adapter để phân tích hành vi và AI predict

### 14.2. Quan hệ với CICFlowMeter

Project không đơn thuần gọi CICFlowMeter như một black-box, mà có cơ chế riêng để sinh flow features. Tuy nhiên, code cho thấy hướng tham chiếu rất rõ tới CIC/CICFlowMeter:

- [core/flow_engine/cic_reference.py](D:/DATN-Packetra/core/flow_engine/cic_reference.py)
- các exporter `export_*_to_cic_csv`
- schema feature mang phong cách CIC

### 14.3. Project hiện hỗ trợ gì ở mức flow export?

- convert toàn bộ capture sang CSV flow
- convert packet được chọn sang CSV flow
- export CSV theo format nội bộ hoặc format tương thích CIC ở nhiều mức

### 14.4. Về cột label khi predict thực tế

Khi dự đoán dữ liệu thật:

- CSV đầu vào cho predict không cần cột `Label`
- `Label` chỉ cần trong dataset train/evaluation

## 15. Dashboard

### 15.1. Dashboard làm gì?

Dashboard dùng để hiển thị góc nhìn tổng quan thay vì bắt người dùng đọc từng packet.

Ví dụ các loại insight có thể đưa lên dashboard:

- top protocol
- packet rate / timeline
- endpoint activity
- conversation distribution
- security investigation view
- HTTP/TLS và DNS patterns

### 15.2. Template dashboard

Templates hiện có trong `data/dashboard_templates/`, ví dụ:

- `template_network_overview.json`
- `template_protocol_analysis.json`
- `template_security_investigation.json`
- `template_timeline_analysis.json`
- `template_topology_view.json`

### 15.3. Import / Export dashboard

Project có:

- import dashboard
- export dashboard JSON
- sample import JSON tại:
  - [help/examples/sample_dashboard_import.json](D:/DATN-Packetra/help/examples/sample_dashboard_import.json)

## 16. Help và tài liệu người dùng

Ngoài README này, project còn có tài liệu HTML để mở trực tiếp trong app:

- `Help > Contents`
- `Help > User Guide`
- `Help > Capture Workflow Guide`
- `Help > Capture Filter Guide`
- `Help > Display Filter Reference`
- `Help > Dashboard Guide`
- `Help > Remote Capture Guide`

Nếu README dùng để onboarding tổng quan, thì thư mục `help/` dùng để hướng dẫn thao tác trực tiếp cho người dùng cuối.

## 17. Hạn chế hiện tại

- Model hiện tại phụ thuộc mạnh vào schema flow và cách chuẩn hóa feature đã dùng khi train.
- Artifact AI trong repo là TorchScript FT-Transformer; nếu bạn thay bằng model khác thì cần giữ tương thích về feature order và preprocessing.
- File `feature_columns.json` không có sẵn trong package hiện tại, nên thứ tự feature đang phụ thuộc vào code.
- Các lớp hiếm như web attack hoặc một số lớp merged/đặc thù có thể vẫn khó học hơn lớp phổ biến.
- Kết quả AI nên xem là công cụ hỗ trợ phân tích, không phải kết luận cuối cùng.
- Local capture trên Windows phụ thuộc Npcap.
- Remote capture phụ thuộc cấu hình host từ xa và môi trường dòng lệnh trên server.
- Project chưa nhằm thay thế hoàn toàn Wireshark hoặc IDS thương mại trong môi trường production.

## 18. Định hướng phát triển tiếp theo

- Hoàn thiện hơn `PacketraFlowEngine` và tài liệu flow schema.
- Đóng gói đầy đủ pipeline train thành script tái lập được ngay trong repo.
- Bổ sung `feature_columns.json` hoặc một manifest inference đầy đủ hơn.
- Hỗ trợ explainable AI / natural-language explanation cho từng prediction.
- Tăng tính ổn định cho lớp hiếm bằng rebalancing, augmentation hoặc dataset bổ sung.
- Bổ sung thêm dataset ngoài CIC-style để đánh giá khả năng tổng quát hóa.
- Mở rộng demo packet theo từng kịch bản tấn công có chú giải rõ hơn.
- Tối ưu dashboard và topology cho capture lớn.
- Đóng gói project thành bản cài đặt dễ dùng cho người mới.

## 19. Tóm tắt ngắn cho người mới

Nếu bạn mới tiếp cận project, hãy hiểu đơn giản như sau:

- `Packetra` đọc packet từ file hoặc capture trực tiếp.
- Sau đó nó cho bạn xem packet ở mức chi tiết.
- Khi cần AI, nó sẽ gom packet thành flow.
- Từ flow, nó sinh feature.
- Model AI dùng feature đó để dự đoán hành vi mạng.
- Dashboard và topology giúp bạn nhìn bức tranh tổng quát nhanh hơn.

## 20. Checklist rà soát README

README này đã bao phủ các nhóm nội dung sau:

- Mục tiêu project
- Chức năng chính
- Cấu trúc thư mục
- Dataset
- Model / artifact AI
- Cài đặt môi trường
- Cách chạy
- Workflow tổng thể
- Phân biệt packet / flow / CSV / dataset / model
- Hạn chế hiện tại
- Future work

Nếu bạn muốn, bước tiếp theo mình có thể làm tiếp một trong hai hướng:

1. viết thêm bản `README.md` theo kiểu học thuật hơn, hợp format luận văn / báo cáo đồ án  
2. viết thêm bản `README_EN.md` tiếng Anh tương ứng với nội dung này
