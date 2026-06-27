# DATN-Packetra

## 1. Tổng quan

`DATN-Packetra` là đồ án xây dựng một phần mềm phân tích gói tin mạng bằng Python và PySide6. Hệ thống không chỉ dừng ở việc mở file PCAP/PCAPNG và xem từng gói tin, mà còn nối liền nhiều lớp chức năng trong cùng một ứng dụng:

- bắt gói tin trực tiếp
- mở và lưu file capture
- phân tích gói tin theo từng giao thức
- lọc, tìm kiếm, theo dõi stream
- gom gói tin thành flow
- xuất dữ liệu flow ra CSV
- phân tích hành vi flow bằng mô hình AI
- hiển thị dashboard
- trực quan hóa topology
- hỗ trợ remote capture qua SSH hoặc agent Windows

Nói ngắn gọn, đây là một công cụ phân tích mạng thiên về học tập, thực hành, minh họa và khảo sát kỹ thuật, với ý tưởng chính là đưa các lớp quan sát từ thấp đến cao vào cùng một môi trường làm việc.

## 2. Mục tiêu đồ án

Đồ án hướng tới các mục tiêu chính sau:

- giúp người dùng quan sát lưu lượng mạng dễ hơn so với việc chỉ nhìn từng gói tin rời rạc
- kết nối được hai góc nhìn: mức gói tin và mức flow
- tạo ra pipeline rõ ràng từ `capture -> packet -> flow -> CSV -> AI -> dashboard/topology`
- hỗ trợ đọc kết quả theo hướng trực quan hơn
- dùng được trong bối cảnh học tập, demo, thực hành phân tích mạng và điều tra kỹ thuật quy mô nhỏ đến trung bình

## 3. Ứng dụng này làm gì từ đầu đến cuối

Luồng xử lý của hệ thống có thể tóm tắt như sau:

```text
Nguồn dữ liệu
-> bắt trực tiếp / mở file / nhận stream remote / dùng demo
-> giải mã từng packet
-> dựng danh sách packet + chi tiết + bytes
-> áp dụng display filter / tìm kiếm / follow stream / thống kê
-> gom packet thành flow
-> tính đặc trưng flow
-> xuất CSV hoặc đưa vào mô hình AI
-> nhận nhãn dự đoán / tóm tắt hành vi
-> trình bày lại qua bảng, topology, dashboard
```

Chi tiết hơn:

1. Người dùng chọn một interface cục bộ, interface remote, named pipe, file PCAP/PCAPNG hoặc file demo.
2. Hệ thống thu packet thô và giải mã bằng Scapy.
3. `PacketParser` chuyển packet thành `PacketRecord`, gắn thông tin thời gian, nguồn, đích, giao thức, cổng, info, metadata và quan hệ stream.
4. Giao diện hiển thị packet list, packet details tree, byte/hex view.
5. Người dùng có thể lọc, tìm, mark, ignore, comment, xem conversations, statistics, capture properties, topology, expert info, ...
6. Khi cần phân tích hành vi, hệ thống gom packet thành các flow hai chiều.
7. Từ flow, hệ thống trích xuất bộ đặc trưng kiểu CIC để xuất CSV hoặc chạy suy luận AI.
8. AI trả về nhãn và độ tin cậy cho từng flow, đồng thời bộ `BehaviorAnalyzer` tạo ra mô tả hành vi ở mức dễ đọc.
9. Dashboard và topology dùng dữ liệu packet hiện đang hiển thị để tạo góc nhìn tổng hợp.

## 4. Các nhóm chức năng chính

## 4.1. Nhóm capture

Hệ thống hỗ trợ nhiều nguồn capture khác nhau:

- live capture cục bộ qua Npcap trên Windows
- đọc stream PCAP/PCAPNG từ named pipe Windows
- remote capture trên Linux qua SSH và `tcpdump`
- remote capture trên Windows qua `PacketraAgent`
- mở file `.pcap` và `.pcapng`
- dùng bộ demo trong thư mục `demo/`

Các thao tác liên quan:

- start / stop / restart capture
- cấu hình capture filter
- chọn promiscuous mode
- cập nhật realtime
- tự cuộn khi đang bắt gói
- tự lưu output theo file format và nén
- rollover theo số packet, kích thước, thời lượng, thời điểm

## 4.2. Nhóm phân tích packet

Đây là phần cốt lõi của ứng dụng:

- bảng packet list
- cây packet details
- cửa sổ byte/hex
- hiển thị giao thức, thời gian, chiều dài, cổng, info
- tính stream index cho Ethernet, IPv4, IPv6, TCP, UDP
- gắn metadata cho request/response của nhiều giao thức
- hỗ trợ follow luồng giao tiếp
- giữ comment cho capture và cho từng packet
- xử lý pcapng metadata như interface, file comment, packet comment

## 4.3. Nhóm display filter và tìm kiếm

Ứng dụng có engine display filter riêng trong `core/filtering.py`, không phụ thuộc Wireshark.

Filter engine hỗ trợ:

- toán tử logic `and`, `or`, `not`
- so sánh `==`, `!=`, `<`, `>`, `<=`, `>=`
- toán tử `contains`
- protocol aliases cho nhiều giao thức
- field filtering như:
  - `frame.number`
  - `frame.len`
  - `protocol`
  - `src`, `dst`
  - `eth.src`, `eth.dst`
  - `ip.src`, `ip.dst`, `ip.ttl`
  - `tcp.port`, `tcp.srcport`, `tcp.dstport`, `tcp.stream`
  - `udp.port`, `udp.srcport`, `udp.dstport`
  - `dns.*`, `http.*`, `tls.*`, `smb2.*`, ...
- protocol hierarchy path để phục vụ lọc sâu hơn

Ngoài filter, hệ thống còn có:

- tìm packet theo nhiều kiểu
- regex search
- case sensitivity
- điều hướng next / previous / first / last

## 4.4. Nhóm thống kê và phân tích hỗ trợ

Trong giao diện có nhiều cửa sổ và công cụ phụ:

- capture summary
- conversations
- protocol distribution
- capture file properties
- capture information theo thời gian thực
- expert information
- custom expert items
- firewall ACL bundle generator

Phần sinh luật tường lửa không chỉ là một hộp thoại phụ. Trong `core/firewall_acl.py`, hệ thống còn có thể lấy thông tin từ packet đang chọn để tạo rule mẫu cho nhiều hệ tường lửa khác nhau như:

- Cisco IOS ACL
- IP Filter
- IPFirewall
- Netfilter `iptables`
- Packet Filter `pf`
- Windows Firewall `netsh`

Các rule này có thể được sinh theo nhiều kiểu khác nhau, ví dụ theo IP nguồn, IP đích, cổng TCP/UDP, cặp IP, hoặc cặp IP kèm cặp cổng.

## 4.5. Nhóm flow và xuất CSV

Flow engine nằm trong `core/flow_engine/`.

Các khả năng chính:

- gom packet thành flow hai chiều
- dùng `FlowKey` và `PacketraFlow` để quản lý từng flow
- hỗ trợ timeout flow
- có chế độ tương thích kiểu CIC
- xuất flow ra nhiều định dạng CSV

Các đường xuất chính:

- CSV header đầy đủ theo bộ đặc trưng nội bộ
- CSV tương thích CIC
- CSV CIC dạng legacy
- CSV source-oriented
- xuất từ packet list đang chọn
- xuất trực tiếp từ file pcap

## 4.6. Nhóm AI

AI trong repo hiện tại là suy luận trên flow, không phải suy luận trực tiếp trên từng packet.

Vai trò của lớp AI:

- chuẩn hóa dữ liệu flow
- scale đặc trưng
- nạp label encoder
- nạp model TorchScript
- dự đoán nhãn cho từng flow
- trả về `prediction`, `label`, `confidence`, `anomaly_score`

Ngoài model, hệ thống còn có lớp `BehaviorAnalyzer` để diễn giải hành vi theo rule-based summary, ví dụ:

- port scan
- SYN scan / SYN flood
- UDP scan / UDP flood
- DNS anomaly
- SSH suspicious activity
- ICMP anomaly

Nghĩa là AI không chỉ trả nhãn, mà ứng dụng còn cố gắng biến kết quả thành đoạn mô tả dễ hiểu hơn.

## 4.7. Nhóm dashboard

Dashboard là một hệ thống riêng khá hoàn chỉnh:

- model dữ liệu dashboard
- repository lưu template và dashboard người dùng
- service layer quản lý tạo, sửa, lưu, nhân bản, import/export
- query engine
- advanced query helpers
- visualization registry
- editor dashboard
- overview dashboard
- thumbnail cache

Về mặt truy vấn dữ liệu, dashboard không chỉ lấy dữ liệu rồi vẽ ngay, mà còn có một lớp xử lý trung gian:

- ghép bộ lọc toàn cục và bộ lọc riêng của từng widget
- lọc theo biểu thức
- group theo một hay nhiều trường
- tính metric như `count`, `distinct_count`, `sum`, `avg`, `min`, `max`, `first`, `last`
- chia bucket thời gian như `1s`, `1m`, `1h`
- sort, limit và chọn cột hiển thị

Ngoài query engine chính, file `gui/dashboard/advanced_queries.py` còn có thêm các công cụ phân tích phụ như:

- tạo pivot table
- lấy top N / bottom N
- tìm outlier theo độ lệch chuẩn
- so sánh theo các khoảng thời gian
- tạo drilldown filter từ dữ liệu người dùng vừa bấm trên biểu đồ

Các visualization có trong build hiện tại:

- `metric`
- `table`
- `bar`
- `horizontal_bar`
- `line`
- `area`
- `scatter`
- `radar`
- `treemap`
- `sunburst`
- `pie`
- `donut`
- `histogram`
- `heatmap`
- `topology`

Các data source cho dashboard:

- `packets`
- `endpoints`
- `conversations`
- `protocol_stats`
- `dns_queries`
- `http_requests`

Dashboard mặc định được seed trong `data/dashboard_templates/` gồm nhiều mẫu như:

- Network Overview
- Protocol Analysis
- Security Investigation
- Endpoint Activity
- Timeline Analysis
- Topology View
- DNS Analysis
- HTTP/TLS Analysis

Ngoài các dashboard mẫu đầy đủ, repository dashboard còn tự dựng một nhóm chart template rút gọn từ các widget mẫu để người dùng có thể tạo nhanh từng biểu đồ lẻ.

Dashboard người dùng được lưu ở:

- `data/dashboards/user_dashboards.json`

## 4.8. Nhóm topology

Topology dùng `QGraphicsView/QGraphicsScene` để trực quan hóa quan hệ giao tiếp:

- node đại diện cho host / endpoint
- edge đại diện cho quan hệ truyền thông
- zoom, pan, chọn node/edge
- kết hợp với conversation stats để giải thích “ai đang nói chuyện với ai”

## 4.9. Nhóm remote capture

Có hai hướng remote capture:

### Linux remote capture

- dùng SSH qua `paramiko`
- gọi `tcpdump -U -w -`
- stream dữ liệu PCAP về ứng dụng
- giao diện quản lý danh sách remote host và interface

### Windows remote capture

- dùng `PacketraAgent`
- agent có thể:
  - liệt kê interface
  - stream packet ra stdout theo định dạng pcap
  - chạy như Windows service
  - bootstrap OpenSSH + Npcap + service

File liên quan:

- `agent/agent_service.py`
- `agent/build_agent_msi.py`
- `data/packetra-remote-agent.zip`

## 4.10. Nhóm tài liệu và trợ giúp

Repo có bộ tài liệu người dùng khá đầy đủ trong `help/`:

- `help/index.html`
- `help/user_guide.html`
- `help/capture_workflow.html`
- `help/capture_filter_guide.html`
- `help/filter_reference.html`
- `help/dashboard_guide.html`
- `help/find_guide.html`
- `help/agent_guide.html`
- `help/agent_guide.md`

Ngoài ra còn có phần báo cáo đồ án và tài liệu nghiên cứu trong `scrap/`:

- `scrap/DATN/` chứa báo cáo LaTeX
- `scrap/full train kaggle.md` chứa notebook / ghi chép huấn luyện rất dài
- `scrap/huong_dan_viet_quyen_do_an_latex.md` là ghi chú viết báo cáo

## 5. Cấu trúc thư mục thực tế của repo

Lưu ý: repo hiện tại **không có** thư mục `docs/` ở root. Phần báo cáo và ghi chép đang nằm trong `scrap/`.

| Đường dẫn | Vai trò |
| --- | --- |
| `main.py` | Entry point chạy ứng dụng |
| `requirements.txt` | Danh sách dependency Python |
| `core/` | Lõi bắt gói, parser, filter, stream, flow engine, remote capture |
| `gui/` | Giao diện PySide6 và phần điều phối chức năng |
| `utils/` | Hỗ trợ IO capture, kiểm tra Npcap, compile check, parser pcapng |
| `ai/` | Artifact AI phục vụ suy luận |
| `data/` | Dashboard template, dashboard người dùng, gói agent |
| `demo/` | Bộ file demo `.pcapng` |
| `help/` | Tài liệu HTML và hướng dẫn dùng hệ thống |
| `image/` | Icon, hình topo, hình layout, toolbar asset |
| `agent/` | Mã agent remote capture trên Windows |
| `scrap/` | Báo cáo đồ án LaTeX và ghi chép nghiên cứu/huấn luyện |

## 6. Các file và module quan trọng

## 6.1. Entry point

### `main.py`

Nhiệm vụ:

- thiết lập biến môi trường để giảm log thừa
- khởi tạo `QApplication`
- kiểm tra Npcap trên Windows
- tạo `ApplicationWindow`
- resize và canh giữa cửa sổ chính

## 6.2. Giao diện chính

### `gui/application.py`

Đây là file lớn nhất và cũng là trung tâm điều phối của toàn bộ ứng dụng. File này phụ trách:

- tạo main window
- menu bar, toolbar, action
- điều phối `CaptureView`
- tích hợp dashboard
- tích hợp AI export / AI analyze
- quản lý remote interface
- hiển thị topology
- quản lý preferences và `QSettings`
- mở các cửa sổ thống kê, conversation, expert info, capture properties, ...

### `gui/capture_view.py`

Đây là widget quan trọng nhất cho phần làm việc với capture:

- duy trì `records` và `visible_indices`
- quản lý live capture và file load
- packet table
- details tree
- bytes view
- display filter
- mark / ignore / comment
- save / load capture
- conversation highlight
- protocol sparkline
- packet minimap
- file format view
- file load thread và refine thread

### Các file giao diện liên quan

- `gui/packet_table.py`: bảng packet
- `gui/packet_details.py`: cây chi tiết packet
- `gui/hex_view.py`: khung byte/hex
- `gui/conversations_dialog.py`: thống kê conversation theo Ethernet / IPv4 / IPv6 / TCP / UDP
- `gui/interface_selector.py`, `gui/interface_selector_view.py`: chọn interface
- `gui/manage_interfaces_dialog.py`: quản lý interface local/remote
- `gui/filter_drag.py`: ô nhập filter và các thao tác kéo/thả filter
- `gui/global_style.py`: theme giao diện

## 6.3. Capture backend

### `core/capture.py`

File này thực hiện:

- local capture với `scapy.sniff`
- remote capture đọc stream PCAP/PCAPNG
- named pipe capture trên Windows
- nhận biết interface identity để lọc packet khi không promiscuous
- decode packet theo `linktype`
- hỗ trợ Ether, IPv4, IPv6, Linux cooked capture, frame preemption / mPacket

Hai lớp chính:

- `PacketSniffer`
- `RemotePacketSniffer`

## 6.4. Parser

### `core/parser.py`

Đây là parser lớn và rất nặng chức năng. Nó chịu trách nhiệm:

- chuyển packet Scapy thành `PacketRecord`
- tính thời gian tương đối, delta thời gian
- đoán giao thức
- dựng `info` tương tự packet summary
- quản lý state cho nhiều giao thức
- quản lý request/response, stream và metadata

Parser theo dõi nhiều ngữ cảnh như:

- TCP stream
- DNS request/response
- HTTP
- SMTP
- IMAP
- SIP
- SNMP
- WHOIS
- ICMP echo
- ICMPv6 echo
- TLS
- QUIC
- SMB2
- DCERPC
- LDAP
- FTP
- TFTP
- RADIUS
- NTP
- SSH
- Kerberos
- H.264 over TS

Nói cách khác, parser không chỉ đọc field đơn giản, mà còn giữ trạng thái để tạo ra thông tin phân tích có ngữ cảnh hơn.

## 6.5. Formatter cho packet details và byte mapping

### `core/formatters.py`

Đây là file rất lớn và rất quan trọng cho trải nghiệm phân tích packet. Nếu `core/parser.py` tạo ra `PacketRecord`, thì `core/formatters.py` chịu trách nhiệm dựng cây chi tiết để hiển thị trong panel packet details và liên kết từng node với vùng byte tương ứng.

Vai trò chính:

- dựng cây phân tích cho rất nhiều giao thức
- ánh xạ node phân tích sang offset/length trong dữ liệu gốc
- hỗ trợ nhiều nguồn byte khác nhau như packet gốc, TCP reassembled payload, payload đã giải mã UTF-8, payload sau giải nén, ...
- hiển thị các đoạn reassembly và expert-style explanation theo dạng cây

Phần này là lý do vì sao ứng dụng không chỉ có bảng packet, mà còn có thể mở rộng xuống mức bóc tách từng lớp giao thức khá sâu ngay trong giao diện.

## 6.6. Filter engine

### `core/filtering.py`

Chứa lớp `DisplayFilter`:

- tokenizer cho biểu thức
- parser logic
- evaluator trên `PacketRecord`
- protocol alias map
- hierarchy path support
- field resolution cho nhiều lớp giao thức

Đây là một thành phần quan trọng vì dashboard, tìm kiếm và điều hướng phân tích đều hưởng lợi từ packet scope đã lọc.

## 6.7. Flow engine

### `core/flow_engine/flow_key.py`

- chuẩn hóa endpoint
- tạo khóa flow hai chiều

### `core/flow_engine/flow.py`

- lưu thống kê của một flow
- tính duration, IAT, packet length stats, flags, bulk stats, active/idle stats

### `core/flow_engine/feature_extractor.py`

- đọc packet list hoặc file pcap
- gom packet thành flow
- có `cic_compat_mode`
- tạo feature row

### `core/flow_engine/csv_exporter.py`

- xuất ra nhiều schema CSV
- hỗ trợ export từ packet list hoặc từ file pcap

### `core/flow_engine/model_adapter.py`

- nạp model
- chuẩn hóa feature matrix
- support TorchScript, XGBoost, sklearn-style model

### `core/flow_engine/behavior_analyzer.py`

- rule-based summary cho flow
- kết hợp với dự đoán model

## 6.8. Dashboard

### `gui/dashboard/models.py`

Định nghĩa toàn bộ model dữ liệu:

- `Dashboard`
- `DashboardWidget`
- `WidgetQuery`
- `VisualizationConfig`
- `DashboardLayout`
- `DashboardSummary`

### `gui/dashboard/repository.py`

- lưu / đọc dashboard người dùng
- lưu / đọc template
- seed template mặc định
- import/export JSON

### `gui/dashboard/query_engine.py`

- registry data source
- filter, group_by, metrics, sort, limit, time_bucket, columns

### `gui/dashboard/advanced_queries.py`

- filter parser cho biểu thức dashboard
- pivot table
- top N / bottom N
- outlier detection
- period comparison
- drilldown filter

### `gui/dashboard/capture_integration.py`

- nối dữ liệu từ `CaptureView` sang dashboard
- tạo các data source như `packets`, `endpoints`, `conversations`, `protocol_stats`, `dns_queries`, `http_requests`
- flatten thêm metadata của packet thành field để query được trực tiếp trong dashboard

### `gui/dashboard/visualization.py`

- renderer cho metric, table, chart, topology
- chart overlay, inspector, label/font/palette logic

### `gui/dashboard/dashboard_overview.py`

- gallery / overview dashboard

### `gui/dashboard/dashboard_editor.py`

- editor kéo-thả, cấu hình widget, đổi layout

## 6.9. Lưu và đọc file capture

### `utils/pcap_io.py`

Chịu trách nhiệm:

- lưu `pcap`
- lưu `pcapng`
- nén `gzip`
- nén `lz4`
- đọc metadata pcapng
- lưu file comment
- lưu packet comment
- clone metadata
- stream packet từ file bằng `iter_pcap_packets`
- đếm packet nhanh với `get_pcap_packet_count`

Ngoài phần IO mức cao, `utils/pcap_io.py` còn gọi xuống `utils/pcapng_parser.py` để:

- đọc comment mức file
- đọc comment theo từng packet
- đọc danh sách interface trong file `pcapng`
- cập nhật lại file comment
- cập nhật lại packet comment ngay trong file `pcapng`

## 6.10. Kiểm tra môi trường

### `utils/system_check.py`

Chức năng:

- kiểm tra Npcap trên Windows
- lấy version, dll path, driver path, service status
- hỗ trợ logic warning lúc khởi động

### `utils/compile_project.py`

- compile check nhanh cho `main.py`, `core/`, `gui/`, `utils/`

## 6.11. Agent Windows

### `agent/agent_service.py`

File này rất quan trọng cho remote capture Windows. Nó hỗ trợ:

- bootstrap cài OpenSSH
- bootstrap cài Npcap
- cài service `PacketraAgent`
- liệt kê interface
- stream packet ra stdout
- chạy như Windows service
- uninstall service

## 7. Mô hình dữ liệu packet trong hệ thống

`core/models.py` định nghĩa `PacketRecord` với các trường:

- `number`
- `epoch_time`
- `relative_time`
- `length`
- `src`
- `dst`
- `protocol`
- `info`
- `layers`
- `sport`
- `dport`
- `stream_hint`
- `metadata`
- `raw`
- `iface`
- `interface_id`
- `marked`
- `ignored`
- `packet_comment`

`PacketRecord` là bản ghi trung gian quan trọng nhất của toàn ứng dụng. Gần như mọi thành phần đều làm việc với nó.

## 8. Pipeline packet -> flow -> AI chi tiết

## 8.1. Bước 1: nhận packet

Nguồn có thể là:

- live capture local
- remote capture
- named pipe
- file pcap/pcapng
- demo dataset

## 8.2. Bước 2: parse thành `PacketRecord`

Parser đưa packet vào các trường chuẩn:

- thông tin khung thời gian
- endpoint
- cổng
- giao thức
- info string
- metadata giao thức

## 8.3. Bước 3: gom packet thành flow

Flow engine dùng:

- `FlowEndpoint`
- `FlowKey`
- `PacketraFlow`

để gom packet cùng quan hệ truyền thông thành flow hai chiều.

## 8.4. Bước 4: trích xuất đặc trưng

`PacketraFlow.to_features()` tạo bộ đặc trưng kiểu IDS / CIC:

- số packet
- số byte
- IAT
- packet length stats
- flag count
- ratio
- active / idle
- window size
- segment size

## 8.5. Bước 5: xuất CSV

Hệ thống có thể xuất:

- CSV nội bộ đầy đủ
- CSV tương thích CIC
- CSV legacy
- CSV source-format

## 8.6. Bước 6: AI inference

Model adapter:

- nhận feature row
- ép kiểu số
- xử lý `NaN`, `inf`
- scale bằng `StandardScaler`
- đưa vào model TorchScript
- lấy class index
- map sang label

## 8.7. Bước 7: diễn giải kết quả

Kết quả không chỉ là nhãn, mà còn có:

- severity
- summary
- possible_behavior
- evidence
- confidence / anomaly_score

## 9. Trạng thái AI hiện tại trong repo

Đây là phần quan trọng cần nói đúng với hiện trạng.

### 9.1. Artifact có trong `ai/`

Hiện repo có:

- `ai/ft_transformer_torchscript.pt`
- `ai/standard_scaler.pkl`
- `ai/label_encoder.pkl`
- `ai/model_info.json`

### 9.2. Model thực tế đang dùng

Theo `gui/application.py`, ứng dụng hiện đang nạp:

- model file: `ft_transformer_torchscript.pt`
- scaler: `standard_scaler.pkl`
- label encoder: `label_encoder.pkl`
- metadata: `model_info.json`

Vì vậy, đường suy luận đóng gói hiện tại là:

- **FT-Transformer TorchScript**

chứ không phải một file XGBoost đang được nạp mặc định trong giao diện.

### 9.3. Điểm lệch giữa metadata và artifact

`ai/model_info.json` vẫn ghi:

- `torchscript_file = ft_transformer_torchscript_cpu.pt`
- `feature_columns_file = feature_columns.json`

nhưng trong thư mục `ai/` hiện tại:

- không có `ft_transformer_torchscript_cpu.pt`
- không có `feature_columns.json`

Ứng dụng vẫn chạy được vì:

- file model thực tế được chỉ định cứng từ `gui/application.py`
- thứ tự feature được sinh từ hằng số `AI_TRAFFIC_COLUMNS` rồi loại các cột metadata

Nói cách khác:

- metadata trong `model_info.json` chưa đồng bộ hoàn toàn với artifact đang commit
- nhưng logic chạy thực tế đã bù bằng feature order nội bộ

Đây là thông tin rất quan trọng nếu sau này cần tái lập pipeline training hoặc đóng gói lại model.

## 10. Bộ nhãn AI

`model_info.json` đang mô tả bộ nhãn 15 lớp:

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

Trong `gui/application.py` còn có một bộ fallback label/description cho phần trình bày kết quả.

## 11. Bộ dữ liệu demo

Thư mục `demo/` chứa rất nhiều file `.pcapng` được đánh số:

- `001.pcapng`
- `002.pcapng`
- ...
- `100.pcapng`

Vai trò:

- test nhanh giao diện
- demo tính năng
- minh họa dashboard, topology, AI
- thao tác mà không cần bắt gói thật

## 12. Dashboard data và persistence

### Template

Template nằm ở:

- `data/dashboard_templates/*.json`

### Dashboard người dùng

Dashboard người dùng nằm ở:

- `data/dashboards/user_dashboards.json`

### Import / export

Hệ thống hỗ trợ:

- export dashboard ra JSON
- import dashboard từ JSON
- nếu `dashboard_id` trùng thì sinh ID mới
- lưu cache dashboard người dùng vào một file JSON duy nhất
- nhân bản dashboard và sinh lại ID cho từng widget
- đổi tên dashboard
- dựng sẵn các chart template rút gọn từ dashboard mẫu

## 13. Capture metadata và PCAPNG

Hệ thống hỗ trợ đọc và lưu một phần metadata của PCAPNG:

- file comment
- section hardware
- section OS
- section application
- interface list
- per-packet comments
- packet-to-interface mapping

Điều này giúp ứng dụng không chỉ xem packet bytes, mà còn giữ được thêm ngữ cảnh của file capture.

Ngoài phần đọc metadata, code còn hỗ trợ ghi ngược một số nội dung trở lại file `pcapng`, chủ yếu là:

- cập nhật comment của toàn file
- cập nhật comment theo từng packet

## 14. Tài liệu báo cáo và nghiên cứu trong repo

### Báo cáo LaTeX

Thư mục:

- `scrap/DATN/`

Chứa:

- `DoAn.tex`
- `Bia.tex`
- `Bia_lot.tex`
- các chương trong `scrap/DATN/Chuong/`
- hình minh họa trong `scrap/DATN/Hinhve/`

### Ghi chép training

File:

- `scrap/full train kaggle.md`

Đây là ghi chép rất dài của quá trình huấn luyện trên Kaggle, bao gồm:

- dọn thư mục output
- kiểm tra dataset
- thống kê cột và đơn vị
- thống kê label
- tiền xử lý
- huấn luyện
- xuất artifact

README này không thay thế file đó, nhưng file đó là nguồn tham khảo chính nếu cần hiểu quá trình training.

## 15. Yêu cầu môi trường

### Hệ điều hành

- Windows là môi trường được hỗ trợ tốt nhất cho live capture cục bộ
- Linux có vai trò ở nhánh remote capture

### Python

- README khuyến nghị dùng Python 3.11 vì file Torch wheel trong `requirements.txt` đang trỏ tới bản `cp311`

### Dependency chính

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

### Phần mềm ngoài Python

- Npcap: bắt buộc cho live capture trên Windows
- OpenSSH: cần cho remote capture trên Windows agent
- `tcpdump`: cần cho remote capture Linux

## 16. Cài đặt và chạy

## 16.1. Tạo môi trường

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 16.2. Chạy ứng dụng

```powershell
python main.py
```

## 16.3. Kiểm tra nhanh code có compile được không

```powershell
python -m py_compile main.py
python utils/compile_project.py
```

## 16.4. Kiểm tra Npcap

Khi chạy trên Windows, `main.py` sẽ kiểm tra Npcap. Nếu thiếu Npcap, ứng dụng sẽ hiện cảnh báo và không cho vào phiên capture local.

## 17. Các luồng sử dụng điển hình

## 17.1. Mở file và phân tích packet

1. Mở file `.pcap` hoặc `.pcapng`
2. Xem packet list
3. Chọn packet để xem details và bytes
4. Áp dụng display filter
5. Tìm packet quan tâm
6. Xem conversations / statistics / topology

## 17.2. Bắt gói trực tiếp

1. Chọn interface
2. Đặt capture filter nếu cần
3. Start capture
4. Theo dõi packet realtime
5. Stop capture
6. Lưu file nếu cần

## 17.3. Xuất flow CSV

1. Mở capture hoặc bắt gói
2. Chọn export flow CSV
3. Hệ thống gom packet thành flow
4. Xuất ra file CSV
5. Đồng thời có thể sinh phần mô tả hành vi flow

## 17.4. Dùng dashboard

1. Mở dashboard overview
2. Chọn template hoặc tạo dashboard mới
3. Dùng packet scope hiện tại làm nguồn dữ liệu
4. Chỉnh widget, query, visualization
5. Lưu hoặc export JSON

## 17.5. Dùng remote capture

### Linux

1. cấu hình host trong giao diện
2. nhập user / auth
3. lấy danh sách interface
4. start capture từ xa
5. nhận stream packet về máy local

### Windows

1. cài `PacketraAgent`
2. chuẩn bị OpenSSH + Npcap
3. kết nối từ GUI
4. list interface
5. capture từ agent

## 18. Những điểm mạnh của đồ án ở mức kỹ thuật

- có giao diện hoàn chỉnh, không chỉ là script proof-of-concept
- parser rất sâu, theo dõi được nhiều state request/response
- có display filter riêng
- có packet comments và pcapng metadata
- có flow engine và CSV pipeline
- có AI inference thật trong ứng dụng
- có dashboard riêng thay vì chỉ hiện bảng
- có topology
- có remote capture Linux và Windows
- có bộ tài liệu HTML khá đầy đủ
- có báo cáo LaTeX ngay trong repo
- có cả phần sinh rule tường lửa mẫu từ packet đang chọn

## 19. Những điểm cần lưu ý hoặc còn chưa đồng bộ

- `README.md` cũ có một số thông tin lệch so với repo hiện tại; bản này đã sửa theo trạng thái thực tế.
- `model_info.json` chưa khớp hoàn toàn với artifact thật trong `ai/`.
- `requirements.txt` vẫn giữ `xgboost`, nhưng nhánh suy luận mặc định hiện tại là TorchScript.
- repo không có một pipeline huấn luyện tái lập hoàn chỉnh kiểu `train.py` một lệnh ở root.
- một số hằng số trong `gui/application.py` còn trỏ tới `docs/...` cũ, trong khi tài liệu báo cáo hiện ở `scrap/`.
- code giao diện tập trung nhiều logic trong `gui/application.py` và `gui/capture_view.py`, nên độ phức tạp bảo trì khá cao.
- `core/formatters.py` rất lớn, nên đây là một trong những khu vực khó bảo trì và khó kiểm thử thủ công nhất của repo.

## 20. File nào nên đọc trước nếu muốn hiểu nhanh repo

Nếu muốn nắm nhanh từ tổng quan đến chi tiết, nên đọc theo thứ tự:

1. `main.py`
2. `gui/application.py`
3. `gui/capture_view.py`
4. `core/capture.py`
5. `core/parser.py`
6. `core/formatters.py`
7. `core/filtering.py`
8. `core/flow_engine/feature_extractor.py`
9. `core/flow_engine/model_adapter.py`
10. `gui/dashboard/capture_integration.py`
11. `gui/dashboard/repository.py`
12. `core/firewall_acl.py`
13. `utils/pcap_io.py`
14. `help/user_guide.html`
15. `scrap/DATN/DoAn.tex`
16. `scrap/full train kaggle.md`

## 21. Kết luận

`DATN-Packetra` là một đồ án phần mềm phân tích mạng có phạm vi tương đối rộng. Nó không chỉ dừng ở việc hiển thị packet, mà còn nối được nhiều lớp xử lý:

```text
capture
-> parse packet
-> filter / inspect / search
-> group thành flow
-> export CSV
-> AI inference
-> dashboard / topology / summary
```

Nếu xem repo này như một hệ thống hoàn chỉnh, thì nó gồm 4 phần lớn:

- phần mềm phân tích packet
- engine flow và AI
- giao diện dashboard/topology
- bộ tài liệu và báo cáo đồ án

README này được viết lại dựa trên trạng thái hiện tại của mã nguồn và tài liệu trong repo, nhằm mô tả đầy đủ ứng dụng đang có gì, dùng gì, chạy như thế nào, và các thành phần liên kết với nhau ra sao.
