implementasikan micro (microservices) sebagai backend menggunakan golang.

database stack :
- postgresql
- ACID Transaction (Prepared query)

API Gateway :
- rest api
- gin (Framework HTTP handler)

struktur proyek :
- clean architecture
- Hexagonal Architecture (Sudah diterapkan di micro "neocentra-bank-be-cs") hanya perlu diisikan logic dan lain lain. namun tetap mengikuti struktur clean architecture dan Hexagonal Architecture.

teknik performa :
- Redis (Mencegah double-submission formulir buka rekening jika user menekan tombol register berkali-kali dalam waktu bersamaan.). workflow :
1. Idempotency Key: Frontend harus menghasilkan sebuah UUID unik (misalnya idempotency-key: f47ac10b-58cc-4372-a567-0e02b2c3d479) untuk setiap sesi register baru dan mengirimkannya di request header.
2. Backend Validation: Backend akan menyimpan kunci tersebut di cache (seperti Redis) dengan waktu kedaluwarsa singkat (misal 5-10 menit). Jika backend menerima request dengan kunci yang sama, backend tidak akan mengeksekusi register baru, melainkan hanya mengembalikan respons dari register yang pertama.
- 

struktur database :
table sudah dibuat di postgresql dan sudah berjalan di port postgres server "5432".
namun anda bisa melihat struktur skema table nya di file "neocentra-bank-be-cs/migrations/v1_schema.sql" dan "neocentra-bank-be-cs/migrations/v1_create_customer_table.up.sql"

validation tech stack :
- go-playground/validator/v10 (Validasi format NIK 16 digit, Email, dan Sanitasi input secara deklaratif di DTO (Data Transfer Object).)

port neocentra-bank-be-cs : 8085