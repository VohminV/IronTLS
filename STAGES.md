# IronTLS — этапы реализации

Документ фиксирует этапы работ, объём текущей версии (v0.2) и критерии готовности.
Все этапы ниже, отмеченные `[x]`, реализованы в этом репозитории и покрыты тестами.

## Область v0.2

Рабочее ядро TLS 1.3 на x86-64 (NASM, Win64 ABI), без внешних криптобиблиотек:

- TLS 1.3 (RFC 8446), cipher suite `TLS_AES_128_GCM_SHA256`;
- аутентификация через внешний PSK (`psk_dhe_ke`, RFC 8446 §4.2.11);
- X25519 ECDHE (`key_share`), RFC 7748;
- клиент и сервер, полностью на ассемблере;
- транспорт — поток байт через API `feed` / `drain` (TCP подключается снаружи);
- Windows x86-64, сборка MinGW-w64 + NASM.

Вне области v0.2 (следующие этапы, см. ниже): сертификаты и подписи,
ChaCha20-Poly1305, TCP/async I/O, HTTP/1.1, HTTP/2, nginx-интеграция.

## Этап 0. Каркас и ABI — `[x]`

- [x] Структуры контекста и константы (`include/irontls.h`, `include/it_offsets.inc`).
- [x] Win64 ABI: сохранение callee-saved регистров, выравнивание стека.
- [x] Базовые утилиты: `memcpy`, `memset`, `memzero`, constant-time сравнение.
- [x] Системный CSPRNG (`BCryptGenRandom`) для random/ClientHello/ServerHello.
- [x] Сборка `build.ps1` и `Makefile`, тестовые исполняемые файлы.

**Готово, когда:** проект собирается одной командой, утилиты покрыты тестами.
Статус: готово.

## Этап 1. SHA-256, HMAC, HKDF — `[x]`

- [x] SHA-256: `init/update/final`, произвольная длина, дробление на блоки.
- [x] HMAC-SHA256: ключи любой длины (включая > 64 байт).
- [x] HKDF-Extract / HKDF-Expand (RFC 5869).
- [x] `HKDF-Expand-Label` и `Derive-Secret` в нотации TLS 1.3 (RFC 8446 §7.1).
- [x] KAT: FIPS 180-2, RFC 4231, RFC 5869.

**Готово, когда:** все KAT проходят побайтно.
Статус: готово.

## Этап 2. AES-128-GCM — `[x]`

- [x] AES-128 key schedule и шифрование блока (AES-NI).
- [x] GHASH (GF(2^128), constant-time по данным).
- [x] GCM seal/open: 96-битный nonce, AAD, проверка тега до расшифрования.
- [x] KAT: NIST GCM (пустой/одноблочный/многоблочный с AAD), негативный тест тега.

**Готово, когда:** NIST-векторы проходят, подмена тега отвергается.
Статус: готово.

## Этап 3. Record layer и key schedule — `[x]`

- [x] Разбор/сборка TLS-записей (5-байтовый заголовок, лимиты длины).
- [x] Защита записей: nonce = IV XOR seq, AAD = заголовок, inner content type,
      zero-padding, счётчики последовательности на каждое направление.
- [x] Key schedule: Early/Handshake/Master Secret, traffic secrets, finished keys.
- [x] Игнорирование legacy CCS, обработка alert и ошибок протокола.
- [x] Проверка целостности записей и порядка handshake-сообщений.

**Готово, когда:** запись шифруется/расшифровывается, tamper отвергается.
Статус: готово.

## Этап 4. PSK handshake client/server — `[x]`

- [x] ClientHello: `supported_versions`, `psk_key_exchange_modes`, `pre_shared_key`.
- [x] ServerHello: выбор PSK, `selected_identity`, проверка версии и suite.
- [x] PSK binder: `ext binder`, Truncate(ClientHello) по RFC 8446 §4.2.11.2.
- [x] EncryptedExtensions, Finished (HMAC), проверка обеих сторон.
- [x] Установка application traffic keys, защищённый обмен данными.
- [x] Строгий разбор расширений, лимиты буферов, constant-time сравнения.

**Готово, когда:** клиент и сервер завершают handshake и обмениваются данными.
Статус: готово.

## Этап 5. Тесты, пример, документация — `[x]`

- [x] `tests/test_crypto.c` — KAT для SHA-256/HMAC/HKDF/AES-GCM.
- [x] `tests/test_tls.c` — loopback client↔server, app data, tamper, повторный обмен.
- [x] `examples/loopback.c` — минимальный пример использования API.
- [x] `build.ps1 test` — полный прогон сборки и тестов.
- [x] README/STAGES: описание текущего состояния и ограничений.

**Готово, когда:** `build.ps1 test` завершается успешно.
Статус: готово.

## Этап 6. X25519 + ECDHE (psk_dhe_ke) — `[x]`

- [x] X25519 по RFC 7748: Montgomery ladder, 5×51-битные limb'ы, constant-time cswap.
- [x] `it_x25519` / `it_x25519_base`; клампинг скаляра, отказ при all-zero результате.
- [x] KAT: RFC 7748 vector1/vector2, Alice/Bob public, shared secret, iterated 1000, low-order reject.
- [x] ClientHello: `supported_versions`, `psk_key_exchange_modes` (`psk_dhe_ke`), `key_share` (x25519).
- [x] ServerHello: `key_share` сервера, вычисление общего секрета на обеих сторонах.
- [x] Key schedule: ECDHE-секрет как IKM первого HKDF-Extract (handshake_secret).
- [x] Тесты: equality общего секрета client↔server, отклонение испорченного `key_share`.

**Готово, когда:** все KAT RFC 7748 проходят, handshake с `psk_dhe_ke` завершается.
Статус: готово.

## Следующие этапы (не входят в v0.2)

7. **Сертификаты** — X.509, RSA-PSS/ECDSA-P256 verify, CertificateVerify.
8. **ChaCha20-Poly1305**, SHA-384, AES-256-GCM.
9. **TCP engine** — Winsock/epoll-подобный слой, non-blocking, пул соединений.
10. **HTTP/1.1 и HTTP/2** поверх TLS.
11. **Nginx compatibility layer** и нагрузочные бенчмарки.

## Правила приёмки

1. Криптографический код не считается готовым без KAT.
2. TLS-сообщения не считаются готовыми без проверки на усечённых,
   переставленных и повреждённых входных данных.
3. Все сравнения секретов и тегов — constant-time.
4. Ошибки не приводят к утечке открытого текста до проверки тега.
5. Секреты затираются при освобождении контекста (`it_tls_clear`).
