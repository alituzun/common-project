# Common Local API (Minimal)

Bu API, gönderdiğin Authorization ve Cookie header'larını aynı şekilde upstream isteğine ekleyerek `user.getXpsRanked` endpoint'ini çağırır.

## Çalıştırma

```powershell
npm install
npm start
```

Adres: http://localhost:3001

## Endpoint: /xps-ranked
- GET veya POST kullanılabilir.
- Aşağıdaki header'ları eklemen yeterli:
  - Authorization: Bearer <RAW_JWT>
  - Cookie: connect.sid=...; cf_clearance=...
  - (Opsiyonel) Address: 0x...

Örnek (Postman):
- Method: GET
- URL: http://localhost:3001/xps-ranked
- Headers:
  - Authorization: Bearer eyJhbGc...
  - Cookie: connect.sid=s:...; cf_clearance=...
  - Address: 0xEb8D41F177e19968273baf9100dAF516084D30Da

Notlar:
- Upstream URL sabittir: https://common.xyz/api/internal/trpc/user.getXpsRanked?input={"limit":50,"cursor":2,"direction":"forward"}
- 403 alırsan, tarayıcıdaki User-Agent ve sec-* başlıklarını da eklemen faydalı olabilir.
- Sağlık kontrolü: GET /health → { ok: true }
