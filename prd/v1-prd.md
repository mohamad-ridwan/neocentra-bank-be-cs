implementasikan micro (microservices) sebagai backend menggunakan golang.

database stack :
- postgresql
- ACID Transaction (Prepared query)

API Gateway :
- rest api
- gin (Framework HTTP handler)

struktur endpoint :
- Route Specifications:
  1. POST /api/v1/customers/register : Endpoint formulir registrasi calon nasabah (nik, full_name, email, phone_number, address). logika dan handler (fungsi) sudah dibuatkan di file "neocentra-bank-be-cs/internal/delivery/http/handler/customer_handler.go" hanya perlu di sesuaikan (update) saja dengan "sistem keamanan".
  2. GET /health : Public healthcheck endpoint. contoh logika dan handler (fungsi) sudah dibuatkan di file "neocentra-bank-be-cs/internal/delivery/http/router.go".

- Middleware Stack:
  1. CORS Middleware : Mengizinkan akses origin global (`Access-Control-Allow-Origin: *`) dan menangani preflight request `OPTIONS`.
  2. Panic Recovery Middleware : Menangkap runtime panic di tengah eksekusi, mencegah server Go mati, dan mengembalikan HTTP response JSON 500 yang rapi.
  3. JWT Authentication Middleware : Validasi token JWT algoritma HS256 dari header `Authorization: Bearer <token>` menggunakan `JWT_SECRET` yang dimuat dari `.env`.
  4. contoh logika dan fungsi middleware sudah dibuatkan di file "neocentra-bank-be-cs/internal/delivery/http/middleware/middleware.go".

PostgreSQL Driver :
- jackc/pgx/v5 (dengan pgxpool). Lebih cepat 2-3x dibandingkan lib/pq standar. Mendukung native binary protocol PostgreSQL dan Connection Pooling otomatis.

struktur proyek :
- clean architecture
- Hexagonal Architecture (Sudah diterapkan di micro "neocentra-bank-be-cs") hanya perlu diisikan logic dan lain lain. namun tetap mengikuti struktur clean architecture dan Hexagonal Architecture.

struktur database :
table sudah dibuat di postgresql dan sudah berjalan di port postgres server "5432".
namun anda bisa melihat struktur skema table nya di file "neocentra-bank-be-cs/migrations/v1_schema.sql" dan "neocentra-bank-be-cs/migrations/v1_create_customer_table.up.sql"

validation tech stack :
- go-playground/validator/v10 (Validasi format NIK 16 digit, Email, dan Sanitasi input secara deklaratif di DTO (Data Transfer Object).)

sistem keamanan :
- Enkripsi Penyimpanan Data (Data at Rest) : 
1. AES-256 (Advanced Encryption Standard): Standar kriptografi simetris kelas militer yang digunakan untuk mengacak NIK, alamat, dan email sebelum disimpan ke dalam database backend.
2. Field-Level Encryption (FLE): Enkripsi diterapkan secara spesifik pada level kolom/field data sensitif (bukan sekadar enkripsi disk/database utuh). Jika database terkompromi atau bocor, data NIK tetap berupa ciphertext acak.
3. Tokenisasi & Masking: NIK dikonversi menjadi token acak non-sensitif untuk pemrosesan operasional harian. Pada tampilan antarmuka staf admin/CS internal, data di-masking (contoh: 3271********0001).
- Manajemen Kunci & Perangkat Keamanan Khusus :
Key Management System (KMS): Mengatur siklus hidup kunci enkripsi secara terpusat, menerapkan Envelope Encryption (kunci data dienkripsi oleh kunci utama), serta melakukan rotasi kunci otomatis berkala (misalnya setiap 90–180 hari).
- Local Key Management System (KMS) Architecture:
  1. Envelope Encryption: Master Key (KEK 256-bit) disimpan di Environment Server untuk mengenkripsi Keyset (DEK) yang tersimpan di tabel PostgreSQL (`kms_keysets`).
  2. Google Tink Integration: Menggunakan SDK `github.com/tink-crypto/tink-go/v2` dengan primitive AES256-GCM AEAD & Associated Authenticated Data (AAD) untuk mencegah tampered ciphertext.
  3. Automatic Zero-Downtime Key Rotation:
     - Rotasi kunci otomatis secara berkala (interval 90 hari) dipicu oleh Goroutine Background Scheduler.
     - Keyset Tink menyimpan Primary Key baru untuk enkripsi data baru dan tetap mempertahankan kunci lama untuk dekripsi data legacy tanpa downtime.
     4. logika dan fungsi kms sudah dibuat di file "neocentra-bank-be-cs/internal/usecase/kms_encryptor.go" dan sudah siap digunakan.

teknik optimasi performa :
- Redis (Mencegah double-submission formulir buka rekening jika user menekan tombol register berkali-kali dalam waktu bersamaan.). workflow :
1. Idempotency Key: Frontend harus menghasilkan sebuah UUID unik (misalnya idempotency-key: f47ac10b-58cc-4372-a567-0e02b2c3d479) untuk setiap sesi register baru dan mengirimkannya di request header.
2. Backend Validation: Backend akan menyimpan kunci tersebut di cache (seperti Redis) dengan waktu kedaluwarsa singkat (misal 5-10 menit). Jika backend menerima request dengan kunci yang sama, backend tidak akan mengeksekusi register baru, melainkan hanya mengembalikan respons dari register yang pertama.
- Redis Infrastructure & Idempotency Strategy:
  1. Dedicated Redis Deployment: Redis 7-Alpine di-deploy secara terisolasi pada Kubernetes lokal (Docker Desktop) dengan port "6379" untuk microservice `neocentra-bank-be-cs`.
  2. Idempotency Key Pattern (`SETNX`):
     - Membaca header `X-Idempotency-Key` dari request frontend.
     - Menggunakan perintah Redis `SETNX` dengan TTL 10 menit untuk mengunci request yang sedang berjalan dan menyimpan ter-cache HTTP response.
     - Mencegah *double-submission* saat tombol registrasi ditekan berulang kali, sehingga request duplikat langsung mendapatkan cached response tanpa menyentuh PostgreSQL (0 DB Hit).
- Goroutine & Concurrency Optimization:
  1. Parallel Validation (Fan-Out/Fan-In): Menggunakan `golang.org/x/sync/errgroup` untuk mengecek keunikan NIK, Email, dan No HP secara eksekusi paralel di database, mengurangi latency validasi hingga 60-70%.
  2. Asynchronous Background Task (Worker Pool): Menggunakan Buffered Channel & Goroutine Worker Pool untuk memproses tugas non-core (seperti pengiriman email notifikasi dan pencatatan audit log) secara non-blocking setelah data profil `PENDING_VERIFICATION` sukses disimpan di DB.
  3. Resource Control & Context Propagation: Menggunakan `context.WithTimeout` untuk menghindari Goroutine leak dan membatasi worker pool agar tidak menghabiskan Connection Pool PostgreSQL.

buatkan port neocentra-bank-be-cs : 8085