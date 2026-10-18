#!/usr/bin/env python3
"""Convert Google Authenticator migration QR code(s) to standard otpauth QR codes.

Usage: python3 decode_auth.py IMAGE_OR_DIRECTORY [OUTPUT_DIRECTORY]
The output contains one QR PNG per account and a text file with provisioning URIs.
Treat the output directory as sensitive: these files can recreate your tokens.
"""

import argparse
import base64
import cv2
import sys
import urllib.parse
from pathlib import Path


def varint(buf, pos):
    result = 0
    shift = 0
    while pos < len(buf):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, pos
        shift += 7
        if shift >= 70:
            raise ValueError("Некорректный varint в данных QR")
    raise ValueError("Обрезанные данные QR")


def fields(buf):
    pos = 0
    while pos < len(buf):
        tag, pos = varint(buf, pos)
        field, wire = tag >> 3, tag & 7
        if field == 0:
            raise ValueError("Некорректный номер поля protobuf")
        if wire == 0:
            value, pos = varint(buf, pos)
        elif wire == 2:
            length, pos = varint(buf, pos)
            end = pos + length
            if end > len(buf):
                raise ValueError("Обрезанное поле protobuf")
            value, pos = buf[pos:end], end
        elif wire == 1:
            end = pos + 8
            if end > len(buf):
                raise ValueError("Обрезанное поле protobuf")
            value, pos = buf[pos:end], end
        elif wire == 5:
            end = pos + 4
            if end > len(buf):
                raise ValueError("Обрезанное поле protobuf")
            value, pos = buf[pos:end], end
        else:
            raise ValueError(f"Неподдерживаемый wire type: {wire}")
        yield field, value


def decode_qr(image_path, detector):
    image = cv2.imread(str(image_path))
    if image is None:
        raise ValueError(f"Не удалось открыть изображение: {image_path}")
    # Dense Google migration QR codes can be too small to decode at screenshot
    # resolution. Try the original first, then enlarge it before giving up.
    for scale in (1, 2, 3):
        candidate = image if scale == 1 else cv2.resize(
            image, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC
        )
        multi = detector.detectAndDecodeMulti(candidate)
        values = [value for value in multi[1] if value] if multi[0] else []
        if values:
            return values
        data, _, _ = detector.detectAndDecode(candidate)
        if data:
            return [data]
    raise ValueError(f"QR-код не найден: {image_path}")


def decode_migration_uri(uri):
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "otpauth-migration" or parsed.netloc != "offline":
        raise ValueError("Это не QR экспорта Google Authenticator")
    query = urllib.parse.parse_qs(parsed.query)
    if not query.get("data"):
        raise ValueError("В QR отсутствует поле data")
    try:
        payload = base64.b64decode(query["data"][0], validate=True)
    except Exception as exc:
        raise ValueError("Не удалось декодировать содержимое QR") from exc

    accounts = []
    for field, value in fields(payload):
        if field != 1:
            continue
        item = dict(fields(value))
        secret = item.get(1)
        if not isinstance(secret, bytes) or not secret:
            continue
        name = item.get(2, b"").decode(errors="replace")
        issuer = item.get(3, b"").decode(errors="replace")
        algorithm = {0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512"}.get(item.get(4, 1))
        digits = {0: 6, 1: 6, 2: 8}.get(item.get(5, 1))
        kind = item.get(6, 2)
        counter = item.get(7, 0)
        if algorithm is None or digits is None or kind not in (1, 2):
            raise ValueError(f"Неподдерживаемые параметры аккаунта: {name or '(без имени)'}")
        accounts.append({
            "secret": secret,
            "name": name,
            "issuer": issuer,
            "algorithm": algorithm,
            "digits": digits,
            "kind": kind,
            "counter": counter,
        })
    return accounts


def provisioning_uri(account):
    name = account["name"] or "Account"
    issuer = account["issuer"]
    label = f"{issuer}:{name}" if issuer and not name.startswith(issuer + ":") else name
    params = {
        "secret": base64.b32encode(account["secret"]).decode("ascii").rstrip("="),
        "issuer": issuer,
        "algorithm": account["algorithm"],
        "digits": str(account["digits"]),
    }
    if account["kind"] == 1:
        params["counter"] = str(account["counter"])
        scheme = "hotp"
    else:
        params["period"] = "30"
        scheme = "totp"
    return f"otpauth://{scheme}/{urllib.parse.quote(label, safe='')}?{urllib.parse.urlencode(params)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Изображение с QR-кодом или папка с изображениями")
    parser.add_argument("output", type=Path, nargs="?", help="Папка результата (по умолчанию рядом с источником)")
    args = parser.parse_args()
    if not args.source.exists():
        parser.error(f"Путь не найден: {args.source}")
    output = args.output or (args.source / "authenticator_import" if args.source.is_dir() else args.source.parent / "authenticator_import")
    output.mkdir(parents=True, exist_ok=True)

    images = sorted(p for p in args.source.iterdir() if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".bmp"}) if args.source.is_dir() else [args.source]
    detector = cv2.QRCodeDetector()
    accounts = []
    for image_path in images:
        for uri in decode_qr(image_path, detector):
            accounts.extend(decode_migration_uri(uri))
    if not accounts:
        raise SystemExit("В QR-кодах не найдено аккаунтов")

    uris = []
    encoder = cv2.QRCodeEncoder_create()
    for index, account in enumerate(accounts, 1):
        uri = provisioning_uri(account)
        uris.append(uri)
        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in (account["issuer"] + "_" + account["name"]))
        filename = f"{index:02d}_{safe_name[:70] or 'account'}.png"
        qr = encoder.encode(uri)
        if not cv2.imwrite(str(output / filename), qr):
            raise OSError(f"Не удалось сохранить QR: {filename}")

    (output / "otpauth_uris.txt").write_text("\n".join(uris) + "\n", encoding="utf-8")
    print(f"Извлечено аккаунтов: {len(accounts)}\n")
    for index, account in enumerate(accounts, 1):
        secret = base64.b32encode(account["secret"]).decode("ascii").rstrip("=")
        print(f"{index}. Аккаунт: {account['name'] or '(без имени)'}")
        print(f"   Сервис: {account['issuer'] or '(не указан)'}")
        print(f"   2FA ключ: {secret}\n")
    print(f"QR-коды для импорта сохранены в: {output}")
    print("Ключи позволяют генерировать коды входа. Не публикуйте и удалите после переноса.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as exc:
        sys.exit(str(exc))
