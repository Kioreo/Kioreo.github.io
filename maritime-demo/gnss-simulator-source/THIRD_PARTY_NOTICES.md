# Third-party source notice

This integrated display directly incorporates and modifies source code from:

- **RMA Naval Cyber Range** — <https://github.com/LaquayL/RMA-Naval-Cyber-Range>
- Upstream revision used: `9a3026836a92aa864599ff240c26a160ad39f297`
- Upstream license: GNU Affero General Public License v3.0 (`LICENSE-RMA-AGPL-3.0.txt`)

Imported source areas:

- `src/containers/gui_attack`: React entry-point, React-Leaflet map/own-ship design, and `boat_stylized.png`/`boat.png` assets.
- `src/containers/gui_instruments`: rudder, bordered panel, metal label, LED panel, seven-segment display, and duo-tone bar components.

Local modifications replace the upstream NMEA WebSocket and NATS inputs with the maritime lab's read-only `/api/state` feed, combine the formerly separate GUI applications into one screen, and add the staged FUXA → Signal K → GNSS → autopilot → Modbus attack chain display.

The copied and modified GUI source is distributed under AGPL-3.0. The complete license text is included in `LICENSE-RMA-AGPL-3.0.txt`.
