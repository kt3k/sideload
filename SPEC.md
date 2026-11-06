# Sideload CLI Specification

Status: Draft v2 (language-agnostic)

Purpose: Define a command-line tool that sideloads an iOS application package (IPA) onto a
connected device using a free or paid Apple developer account, plus the minimum set of
diagnostic commands needed when that installation fails.

Upstream reference: [Dadoum/Sideloader](https://github.com/Dadoum/Sideloader) `frontends/cli`
(commit `ed89e28`). This specification is a reduced, corrected subset of that CLI.

## Normative Language

The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `RECOMMENDED`, `MAY`, and
`OPTIONAL` in this document are to be interpreted as described in RFC 2119.

`Implementation-defined` means the behavior is part of the implementation contract, but this
specification does not prescribe one universal policy. Implementations MUST document the selected
behavior.

本文の記述は日本語で行い、規範キーワードは上記の英語表記をそのまま用いる。

## 1. Problem Statement

Sideload CLI は、Apple 開発者アカウント（無料アカウントを含む）を使って、IPA ファイルを USB 接続された
iOS デバイスにインストールするコマンドラインツールである。

本ツールは次の問題を解決する。

- Xcode や macOS を使わずに、1 コマンドで「デバイス登録 → 証明書準備 → App ID 登録 → プロファイル取得
  → 署名 → 転送・インストール」までを行えるようにする。
- 無料アカウントの厳しい制限（App ID は 7 日間で 10 個、証明書数の上限など）に起因する失敗を、
  原因が特定できる形で報告し、利用者が自力で解消できる手段を提供する。
- 上流の Sideloader CLI にある機能のうち、インストールに不要なものを除き、既知の不具合を修正する。

重要な境界:

- 本ツールが扱う Apple 側のリソースは、デバイス・開発証明書・App ID・App Group・
  プロビジョニングプロファイルに限られる。
- 本ツールは Apple 側の状態を一時的に変更する（App ID の登録など）。一部の変更は取り消しても
  枠が回復しない（Section 13.4）。変更を伴わずに見通しを得る手段として `--dry-run` を提供する。

## 2. Goals and Non-Goals

### 2.1 Goals

- `install` コマンド 1 つで IPA をデバイスにインストールできる。
- インストール失敗時の原因を、失敗した処理段階とエラー種別で報告する。
- 失敗の原因（上限到達・不整合）を調べて解消するためのデバッグ用コマンドを提供する。
- 対話式の入力と環境変数の両方で認証情報を受け取れる。
- ローカルの ADI と、リモートの Anisette サーバーの両方に対応する。
- 上流の Sideloader と設定ディレクトリ・鍵ファイルを共有でき、相互に乗り換えられる。

### 2.2 Non-Goals

- `sign`（単体署名）、`trollsign`、`tool`（SideStore のペアリングファイル）など、
  インストールに不要な上流のコマンド。
- 認証情報やログインセッションの永続化（キーリング連携を含む）。
- 2FA を含むログインの完全な無人化。2FA コードは常に利用者が入力する。
- GUI。
- iOS 以外のプラットフォーム（tvOS、watchOS 単体アプリ、macOS）向けのインストール。
- Wi-Fi 経由のデバイス接続を必須とすること（実装が対応する場合は Implementation-defined）。

## 3. System Overview

### 3.1 Main Components

1. `CLI Front End`
   - コマンドライン引数を解析し、検証する。
   - サブコマンドを振り分け、終了コードを決める。

2. `Config Layer`
   - CLI オプション・環境変数・既定値から、型付きの設定値を解決する（Section 6）。
   - 設定ディレクトリの場所を決める。

3. `Credential Provider`
   - Apple ID・パスワード・2FA コードを、環境変数または対話入力から取得する（Section 9.2）。

4. `Anisette Provider`
   - Apple の認証に必要な Anisette データを生成する。
   - ローカル ADI（Android 用ライブラリを読み込む）とリモートサーバーの 2 方式を持つ。

5. `Developer Service Client`
   - Apple の認証（GSA）と Developer Services API を呼び出す。

6. `Device Client`
   - usbmuxd 経由で接続中のデバイスを列挙し、lockdown・AFC・installation_proxy・misagent と通信する。

7. `Bundle Processor`
   - IPA を展開し、Bundle ID・表示名・Extension を書き換える。

8. `Code Signer`
   - Mach-O バイナリと Bundle を、証明書・秘密鍵・プロファイルで署名する。

9. `Install Pipeline`
   - 上記コンポーネントを組み合わせ、Section 7 の手順でインストールを行う。

10. `Output / Logging`
    - 進捗表示、一覧表示、ログ、エラー報告を行う。

### 3.2 Abstraction Levels

移植しやすくするため、次の層に分けて実装することを RECOMMENDED とする。

1. `Interface Layer`: CLI Front End、Output / Logging。
2. `Configuration Layer`: Config Layer、Credential Provider。
3. `Coordination Layer`: Install Pipeline、各デバッグ用コマンドの処理。
4. `Integration Layer`: Anisette Provider、Developer Service Client、Device Client。
5. `Artifact Layer`: Bundle Processor、Code Signer。

### 3.3 External Dependencies

- Apple の認証サーバーと Developer Services API（HTTPS）。
- ローカル ADI を使う場合: ADI ライブラリ（`libstoreservicescore.so`、`libCoreADI.so`）と、
  その初回ダウンロード用のネットワーク接続。
- リモート Anisette を使う場合: anisette-v3 互換のサーバー。
- usbmuxd（Linux では usbmuxd デーモン、macOS では標準、Windows では Apple Mobile Device Support）。
- 設定ディレクトリと作業ディレクトリのためのローカルファイルシステム。

## 4. Core Domain Model

### 4.1 Entities

#### 4.1.1 Configuration Directory

本ツールが永続的に保持するデータの置き場所。場所は Section 6.3 で決める。

Layout:

- `lib/libstoreservicescore.so`、`lib/libCoreADI.so`
  - ローカル ADI 用ライブラリ。存在しなければ自動でダウンロードする。
- `lib/` 配下の ADI プロビジョニング状態
  - Implementation-defined。上流と互換であることが RECOMMENDED。
- `keys/<key_id>/key.pem`
  - 署名用の RSA 2048 ビット秘密鍵（PEM, PKCS#8）。`<key_id>` は Section 4.2 で定義する。

#### 4.1.2 Credentials

- `apple_id` (string)
  - REQUIRED。利用者が入力した値をそのまま使う（正規化しない）。
- `password` (string)
  - REQUIRED。保存してはならない（MUST NOT）。
- `two_factor_code` (string or null)
  - Apple が要求した場合だけ取得する。

#### 4.1.3 Team

- `team_id` (string): REQUIRED。Apple が発行するチーム ID。
- `name` (string)

#### 4.1.4 Registered Device

アカウントに登録済みのデバイス。

- `device_id` (string): Apple 側の識別子。`device delete` の引数に使う。
- `udid` (string): デバイスの UDID（上流では `deviceNumber`）。
- `name` (string)

#### 4.1.5 Connected Device

usbmuxd から見えている接続中のデバイス。

- `udid` (string)
- `name` (string or null): lockdown から取得する端末名。

#### 4.1.6 Development Certificate

- `serial_number` (string)
- `name` (string)
- `machine_name` (string)
  - 本ツールが作成する証明書では、定数 `Sideloader` でなければならない（MUST）。
    上流との互換のため、実行ファイル名に関係なくこの値を使う。
- `certificate_id` (string)
- `content` (bytes): DER 形式の X.509 証明書。

#### 4.1.7 App ID

- `identifier` (string): Bundle ID。
- `name` (string)
- `expiration_date` (timestamp)
- `features` (map): App Group が有効かどうかを含む。

App ID の一覧取得では、あわせて `available_quantity`（残り枠）と `max_quantity`（上限）を得る。

#### 4.1.8 App Group

- `identifier` (string): `group.` で始まる。
- `name` (string)

#### 4.1.9 Provisioning Profile

- `app_id` (string): 対象の App ID。
- `encoded_profile` (bytes): `.mobileprovision` の内容。

#### 4.1.10 App Bundle

作業ディレクトリに展開された `.app`。

- `bundle_identifier` (string): `Info.plist` の `CFBundleIdentifier`。
- `bundle_name` (string)
- `display_name` (string or null): `CFBundleDisplayName`。
- `extensions` (list of App Bundle): `PlugIns/*.appex` と `Watch/*.app`。

#### 4.1.11 Install Plan

`install` が実行前に組み立てる計画。`--dry-run` ではこれを表示して終了する（Section 7.5）。

- `team` (Team)
- `device_udid` (string or null)
- `device_action` (`none` | `register` | `skip`)
- `certificate_action` (`reuse <serial>` | `create` | `revoke_and_create <serials>`)
- `app_ids` (list of `{identifier, exists}`)
- `app_ids_to_register` (integer)
- `available_quantity` (integer)
- `app_group` (`{identifier, exists}`)
- `feasible` (boolean) と、`false` の場合の理由（エラー種別）

### 4.2 Stable Identifiers and Normalization Rules

- `Key ID`
  - `apple_id` の SHA-1 ハッシュを 16 進小文字で表したもの。
  - 鍵ファイルのパスは `<config_dir>/keys/<key_id>/key.pem`。
- `Main Bundle ID`
  - `--bundle-id` が指定されていればその値。
  - 指定されていなければ `<元の CFBundleIdentifier>.<team_id>`。
- `Extension Bundle ID`
  - 各 Extension の元の Bundle ID は、本体の元の Bundle ID で始まり、それより長くなければならない（MUST）。
    満たさなければ `bundle_invalid` とする。
  - 新しい ID は `<Main Bundle ID>` に、元の ID から本体の元の Bundle ID を除いた残りを連結したもの。
- `App ID Name`
  - Bundle 名から英数字以外の文字を除いたもの。空になる場合は Bundle ID を使う。
- `App Group ID`
  - `group.<Main Bundle ID>`。名前は `app group for <本体 App ID の名前>`。
- `Sideloader Certificate`
  - `machine_name == "Sideloader"` の開発証明書。
- `Matching Certificate`
  - Sideloader Certificate のうち、公開鍵がローカルの秘密鍵と一致するもの。
- `Identifier Match`
  - `cert revoke`、`app-id delete` などの引数との照合は完全一致で行う（大文字と小文字を区別する）。

## 5. Command-Line Interface Specification

### 5.1 Executable Name

実行ファイル名は Implementation-defined とする。

- 本リポジトリの実装では `sideload` とする。
- 本文中の例では `<cli>` と表記する。
- 環境変数の接頭辞（`SIDELOADER_`）、設定ディレクトリ名（`Sideloader`）、証明書のマシン名
  （`Sideloader`）は、実行ファイル名に関係なく固定とする（MUST）。上流との互換のためである。

### 5.2 Command Tree

```text
<cli> [global options] <command>

<cli> install <ipa> [install options]     IPA をデバイスにインストールする

# 診断用（Section 8）
<cli> team list                           ログイン確認とチーム ID の確認
<cli> device list [--udid <UDID>]         登録済みデバイスと接続中デバイス
<cli> device delete <device_id>           デバイスの登録解除
<cli> cert list                           開発証明書の一覧
<cli> cert revoke <serial_number>         開発証明書の失効
<cli> app-id list                         App ID の一覧と残り枠
<cli> app-id delete <identifier>          App ID の削除

<cli> version                             バージョン表示
```

`--team <team_id>` は `install` と、`team list`・`version` 以外の診断用コマンドで受け付ける。

### 5.3 Global Options

グローバルオプションはサブコマンドより前に置く。

- `-d`, `--debug`
  - ログレベルを最も詳細なもの（TRACE 相当）にする。
- `--thread-count <N>`
  - 署名の並列数。正の整数。既定値は論理 CPU 数。
- `--anisette-server <URL>`
  - 指定するとリモートの Anisette サーバーを使う。指定しなければローカル ADI を使う。

### 5.4 Install Options

- `<ipa>`: REQUIRED。Section 5.6 の検証を満たすこと。
- `--udid <UDID>`: 対象デバイス。
- `--team <team_id>`: 使用するチーム。
- `-o`, `--output <path>`: 署名済み IPA を書き出し、インストールはしない。
- `--dry-run`: 計画だけを表示する。Apple 側もデバイスも変更しない。
- `--strip-extensions`: Extension と Watch アプリを削除してから処理する。
- `--bundle-id <id>`: 本体の Bundle ID を指定する（Section 4.2）。
- `--name <name>`: `CFBundleDisplayName` を書き換える。
- `--new-cert`: 既存の証明書を再利用せず、作り直す（Section 7.3）。
- `--keep-temp`: 作業ディレクトリを削除しない。

`--output` と `--dry-run` は同時に指定できない（MUST reject、`invalid_arguments`）。

### 5.5 Exit Codes

- `0`: 成功。`--dry-run` で計画が実行可能（`feasible = true`）な場合を含む。
- `1`: 失敗。Section 13.1 のいずれかのエラー。`--dry-run` で計画が実行不可能な場合を含む。

引数解析の失敗も `1` とする。ヘルプ表示（`--help`）は `0` とする。

### 5.6 Argument Validation and Error Surface

ログインやデバイス通信を始める前に、次を検証しなければならない（MUST）。

- `<ipa>` が存在し、通常ファイルであり、拡張子が `.ipa` であること → 満たさなければ `ipa_not_found` / `ipa_invalid`。
- `--output` と `--dry-run` が同時に指定されていないこと → `invalid_arguments`。
- `--output` の書き出し先の親ディレクトリが存在すること → `output_write_failed`。
- `--thread-count` が正の整数であること → `invalid_arguments`。
- `--anisette-server` が `http` または `https` の URL であること → `invalid_arguments`。
- `--bundle-id` が Bundle ID として有効な文字（`[A-Za-z0-9.-]`）だけからなること → `invalid_arguments`。

## 6. Configuration Specification

### 6.1 Configuration Resolution Pipeline

各設定値は次の優先順位で解決する。

1. CLI オプション
2. 環境変数（Section 6.2）
3. 対話入力（認証情報のみ。Section 9.2）
4. 既定値

CLI オプションと環境変数の両方がある場合は、CLI オプションを使う（MUST）。

### 6.2 Environment Variables

- `SIDELOADER_CONFIG_DIR`
  - 設定ディレクトリを上書きする。
- `SIDELOADER_ANISETTE_SERVER`
  - `--anisette-server` の既定値。
- `SIDELOADER_APPLE_ID`
  - Apple ID。設定されていれば Apple ID の入力を求めない。
- `SIDELOADER_APPLE_PASSWORD`
  - パスワード。設定されていればパスワードの入力を求めない。

空文字列の環境変数は、設定されていないものとして扱う（MUST）。

### 6.3 Configuration Directory Resolution

1. `SIDELOADER_CONFIG_DIR` が設定されていれば、その値を使う。
2. 設定されていなければ、OS ごとの既定値を使う。
   - Linux など: `${XDG_CONFIG_HOME:-~/.config}/Sideloader`
   - macOS: `~/Library/Preferences/Sideloader`
   - Windows: `%AppData%\Sideloader`

ディレクトリが存在しなければ作成する。

### 6.4 Core Config Fields Summary (Cheat Sheet)

この節は意図的に他の節と重複させている。

- `debug`: boolean、既定 `false`、`-d` / `--debug`
- `thread_count`: 正の整数、既定は論理 CPU 数、`--thread-count`
- `anisette_server`: URL または null、既定 null、`--anisette-server` > `SIDELOADER_ANISETTE_SERVER`
- `config_dir`: パス、`SIDELOADER_CONFIG_DIR` > OS 既定値
- `apple_id`: 文字列、`SIDELOADER_APPLE_ID` > 対話入力
- `password`: 文字列、`SIDELOADER_APPLE_PASSWORD` > 対話入力（エコーなし）
- `team_id`: 文字列または null、既定 null（最初のチーム）、`--team`
- `udid`: 文字列または null、既定 null（自動選択）、`--udid`

## 7. Install Pipeline

### 7.1 Modes

`install` は次のいずれかのモードで動く。

- `Install`（既定）: デバイスにインストールする。
- `Output`（`--output`）: 署名済み IPA を書き出す。デバイスへの接続は OPTIONAL。
- `DryRun`（`--dry-run`）: Install Plan を表示して終了する。Apple 側への書き込み、デバイスへの書き込み、
  設定ディレクトリへの書き込み（鍵の生成を含む）を一切行ってはならない（MUST NOT）。

### 7.2 Phases

インストールは次の段階を順に進む。各段階の名前は進捗表示とエラー報告に使う（MUST）。

1. `ValidatingArguments`: Section 5.6 の検証。
2. `PreparingBundle`: IPA を作業ディレクトリに展開し、`--strip-extensions` と `--name` を適用する。
3. `SelectingDevice`: Section 10.1 の規則で対象デバイスを決める。
4. `PreparingAnisette`: Anisette Provider を準備する。
5. `LoggingIn`: Section 9.2 の手順でログインする。
6. `SelectingTeam`: Section 9.3 の規則でチームを決める。
7. `Planning`: Apple 側の状態を読み取り、Install Plan を組み立てる。`feasible = false` なら
   ここで失敗する（`DryRun` では計画を表示してから終了コード 1 で終わる）。
8. `RegisteringDevice`: 必要ならデバイスを登録する。
9. `PreparingCertificate`: Section 7.3 の規則で証明書を用意する。
10. `RegisteringAppIds`: 不足している App ID を登録する。
11. `ConfiguringAppGroup`: 全 App ID で App Group を有効にし、App Group を作成または再利用して割り当てる。
12. `FetchingProfiles`: App ID ごとに、その App ID のプロビジョニングプロファイルを取得する。
13. `Signing`: 本体と Extension を署名する。
14. `Delivering`: `Install` モードではデバイスに転送してインストールする（Section 10.3）。
    `Output` モードでは署名済み IPA を書き出す。
15. `CleaningUp`: `--keep-temp` が無ければ作業ディレクトリを削除する。

終了状態:

- `Succeeded`: `Done.` を表示し、終了コード 0。
- `PlanReported`: `DryRun` で計画を表示した。`feasible` に応じて終了コード 0 または 1。
- `Failed`: エラー種別と失敗した段階を表示し、終了コード 1。

ローカルだけで判定できる失敗（引数、IPA、デバイス選択）は、認証情報を求める前に報告しなければならない
（MUST）。そのため段階 2・3 は段階 5 より前に置く。

### 7.3 Certificate Preparation Rules

`--new-cert` が指定されていない場合:

1. 鍵ファイルが存在すれば読み込む。存在しなければ RSA 2048 ビットの鍵を生成して保存する。
2. Matching Certificate があれば、それを使う。
3. 無ければ、鍵から CSR を作って提出し、発行された証明書を使う。

`--new-cert` が指定された場合:

1. 失効させる Sideloader Certificate の一覧（名前とシリアル番号）を表示する。
2. それらをすべて失効させる。
3. 新しい鍵を生成して鍵ファイルを置き換え、CSR を提出する。

`Planning` 段階では、上記のどの処理になるかを `certificate_action` に記録する。

CSR の Subject は Implementation-defined とする（上流は `C=US, ST=STATE, L=LOCAL, O=ORGANIZATION, CN=CN`）。

### 7.4 App ID Registration Rules

- 必要な App ID は、本体と（`--strip-extensions` の適用後に残った）Extension の Bundle ID である。
- 登録済みの App ID と一致しないものを `app_ids_to_register` とする。
- `app_ids_to_register` が `available_quantity` を超える場合、1 つも登録してはならない（MUST NOT）。
  `app_id_quota_exceeded` とし、登録済み App ID のうち最も早い `expiration_date` を表示する。

### 7.5 Dry-Run Plan Output

`DryRun` モードでは、段階 7 の終了時に次の形式で計画を表示する。各行の書式は Implementation-defined だが、
すべての項目を含めなければならない（MUST）。

```text
Team:         <name> (<team_id>)
Device:       <udid> (registered | will be registered | skipped)
Certificate:  reuse <serial> | will create new | will revoke <serial>, ... and create new
App IDs:      need N, already registered M, will register K (available: A / max: X)
  - <bundle_id> (exists | new)
App Group:    group.<main_bundle_id> (exists | new)
Result:       OK | NG: <error_code> <理由>
```

### 7.6 Idempotency and Re-run Rules

- 登録済みのデバイス・App ID・App Group は再利用し、重複して作成してはならない（MUST NOT）。
- 途中で失敗した `install` を再実行したとき、前回の実行で作成済みのリソースを再利用して続行できなければ
  ならない（MUST）。
- 鍵ファイルは、`--new-cert` 以外では上書きしてはならない（MUST NOT）。

## 8. Diagnostic Commands

診断用コマンドは、`install` の失敗原因を調べたり解消したりするためのものである。
`version` を除き、すべてログインを行う（Section 9.2）。`team list` 以外は `--team` を受け付ける。

### 8.1 `team list`

ログインできることを確かめ、`--team` に指定できる ID を表示する。

```text
Teams:
 - `<name>`, with ID `<team_id>`.
```

### 8.2 `device list [--udid <UDID>]`

- 登録済みデバイスをすべて表示する。接続中のものには `(connected)` を付ける。
- 接続中だが未登録のデバイスを別に表示する。
- デバイスが 1 台も接続されていなくても、エラーにしてはならない（MUST NOT）。
- `--udid` を指定した場合は、そのデバイスに関する行だけを表示する。

```text
You have N devices registered.
 - Device `<name>` of UDID `<udid>` with the identifier `<device_id>` (connected)
Connected devices not registered:
 - `<udid>`
```

### 8.3 `device delete <device_id>`

- 引数は UDID ではなく `device_id` である。ヘルプにそう明記する（MUST）。
- 一致するデバイスが無ければ `device_not_found`。

### 8.4 `cert list`

```text
You have N certificates registered.
 - `<name>` with the serial number `<serial>`, from the machine named `<machine_name>`.
```

Matching Certificate には `(this machine)` を付けることを RECOMMENDED とする。

### 8.5 `cert revoke <serial_number>`

- 一致する証明書が 0 件なら `certificate_not_found`。
- 2 件以上一致したら、何もせずに `ambiguous_match`。
- 失効させた証明書で署名したアプリは起動できなくなる。ヘルプにそう明記する（MUST）。

### 8.6 `app-id list`

```text
You have <available> App IDs available out of the <max> you have at your disposal.
 - `<identifier>` for the app `<name>`, expiring on <date>.
```

### 8.7 `app-id delete <identifier>`

- 照合の規則は `cert revoke` と同じ（`app_id_not_found` / `ambiguous_match`）。
- 削除しても登録枠は回復しない。ヘルプにそう明記する（MUST）。

### 8.8 `version`

バージョン文字列を表示する。ログインもデバイス通信も行わない。

## 9. Apple Account Integration Contract

### 9.1 Anisette Provider

- ローカル ADI の場合:
  - ADI ライブラリが設定ディレクトリに無ければダウンロードし、進捗（%）を表示する。
  - ダウンロードに失敗したら `adi_download_failed`、初期化に失敗したら `anisette_unavailable`。
- リモートの場合:
  - ADI ライブラリをダウンロードしてはならない（MUST NOT）。
  - サーバーに接続できない、または応答が不正なら `anisette_unavailable`。
- どちらの方式でも、エラーメッセージに `--anisette-server`（またはローカル ADI への切り替え）の
  提案を含めることを RECOMMENDED とする。

### 9.2 Login Flow

1. `apple_id` を解決する: `SIDELOADER_APPLE_ID` → 対話入力。
2. `password` を解決する: `SIDELOADER_APPLE_PASSWORD` → 対話入力。
   - 対話入力ではエコーしてはならない（MUST NOT）。エコーを止められないプラットフォームでは、
     入力前に警告を表示しなければならない（MUST）。
3. 対話入力が必要なのに標準入力が端末でない場合、入力を待たずに `credentials_unavailable` とする（MUST）。
4. 認証を行う。失敗したら `login_failed`（Apple が返した説明とコードを含める）。
5. 2FA を求められたら、標準入力から 1 行ずつコードを読む。
   - 端末でなくても読んでよい（パイプからの入力を許す）。
   - `resend` と入力されたらコードを再送し、再び入力を待つ。
   - 誤ったコードは再入力を求める。標準入力が EOF になったら `two_factor_failed`。
6. 認証情報とセッションは保存しない。

### 9.3 Team Selection

- `--team` が無ければ、チーム一覧の最初のチームを使う。
- `--team` があれば、`team_id` が完全一致するチームを使う。無ければ `team_not_found`。
- チームが 1 つも無ければ `team_not_found`。

### 9.4 Required Developer Service Operations

Developer Service Client は少なくとも次の操作を提供しなければならない（MUST）。いずれも iOS 向けである。

- `list_teams()`
- `list_devices(team)`、`add_device(team, name, udid)`、`delete_device(team, device_id)`
- `list_development_certs(team)`、`submit_development_csr(team, csr_pem) -> certificate_id`、
  `revoke_development_cert(team, cert)`
- `list_app_ids(team) -> {app_ids, available_quantity, max_quantity}`、
  `add_app_id(team, identifier, name)`、`update_app_id(team, app_id, features)`、
  `delete_app_id(team, app_id)`
- `list_app_groups(team)`、`add_app_group(team, identifier, name)`、
  `assign_app_group(team, app_id, app_group)`
- `download_team_provisioning_profile(team, app_id)`

### 9.5 Error Mapping

- 通信の失敗（接続できない、タイムアウト）→ `apple_transport_error`。
- Apple が返したアプリケーションエラー → 操作に応じた種別（Section 13.1）。
  該当するものが無ければ `apple_api_error`。メッセージには Apple が返した結果コードと説明を含める（MUST）。
- 応答が解析できない → `apple_api_error`（`--debug` では応答の内容を記録する）。

## 10. Device Integration Contract

### 10.1 Device Selection

- `--udid` がある場合:
  - そのデバイスが接続されていればそれを使う。
  - 接続されていない場合、`Install` モードでは `device_not_connected`。`Output` モードと `DryRun` モードでは、
    接続されていなくても UDID として使う。
- `--udid` が無い場合:
  - 接続中のデバイスが 1 台ならそれを使う。
  - 0 台の場合、`Install` モードでは `no_device_connected`。`Output` モードと `DryRun` モードではデバイス無しで
    続行する（`device_action = skip`、警告を表示する）。
  - 2 台以上なら、どのモードでも `multiple_devices_connected`（`--udid` の指定を促す）。

### 10.2 Device Registration

- 対象デバイスの UDID が未登録なら登録する。
- 端末名は lockdown から取得する。取得できない場合（デバイスが接続されていない場合を含む）は UDID を使う。
- 対象デバイスが無い場合（`skip`）は登録しない。このときプロファイルの対象は登録済みのデバイスだけになる。

### 10.3 Delivery to Device

1. lockdown に接続し、installation_proxy、misagent、AFC の各サービスを開始する。
2. AFC で `PublicStaging` を用意する。既に存在する場合は中身ごと削除してから作り直す。
3. `PublicStaging/<.app のディレクトリ名>` に、署名済みの Bundle をすべて転送する。
4. 取得したプロビジョニングプロファイルを misagent でデバイスに入れる。
5. installation_proxy に `PackageType = Developer` を指定してインストールを依頼し、完了まで進捗を表示する。
6. installation_proxy がエラーを返したら `install_failed` とし、`Error`、`ErrorDescription`、`ErrorDetail` を表示する。

ペアリングされていない、またはデバイスがロックされているために lockdown に接続できない場合は
`device_not_paired` とし、デバイス側で「このコンピュータを信頼」する必要があることを表示する（SHOULD）。

## 11. Bundle Processing and Signing Contract

### 11.1 Bundle Processing

- IPA は `Payload/<名前>.app` をちょうど 1 つ含んでいなければならない（MUST）。満たさなければ `ipa_invalid`。
- `--strip-extensions`: `PlugIns/` と `Watch/` を削除する。
- `--name`: 本体の `CFBundleDisplayName` を設定する。
- Bundle ID を Section 4.2 の規則で書き換える。
- 本体の Bundle ID（書き換え前）が `com.SideStore.SideStore` の場合は、`Info.plist` の `ALTAppGroups` を
  `[<App Group ID>]` に設定する。

### 11.2 Signing

- 本体と各 Extension を、それぞれの App ID のプロファイルと証明書・秘密鍵で署名する（MUST）。
  上流のように、すべてを本体のプロファイルで署名してはならない（MUST NOT）。
- エンタイトルメントはプロファイルから導出する。導出の詳細は Implementation-defined。
- 並列数は `thread_count` に従う。`1` の場合は逐次処理とする。
- 失敗したら `signing_failed` とし、失敗したファイルのパスを含める。

### 11.3 Output Mode

- 署名済みの `Payload/` を IPA（ZIP）として `--output` のパスに書き出す。
- 書き出しは一時ファイルに書いてから置き換える方式で行い、失敗時に不完全なファイルを残さないことを
  RECOMMENDED とする。

## 12. Logging, Progress, and Output

- 一覧などのコマンドの結果は標準出力に出す。ログ・進捗・エラーは標準エラー出力に出す（MUST）。
- 既定のログレベルは INFO 相当。`--debug` で TRACE 相当にする。
- `install` は Section 7.2 の段階名と、全体の進捗率を表示する。
  標準エラー出力が端末でない場合は、進捗バーではなく段階ごとに 1 行ずつ出力することを RECOMMENDED とする。
- エラーは `error[<error_code>] (<phase>): <message>` の形式で表示する。`<phase>` は `install` の場合だけ付ける。
- `--debug` では、例外の詳細（スタックトレース、HTTP の要求と応答の要約）を出してよい（MAY）。
  ただし Section 14.2 の秘密情報を含めてはならない（MUST NOT）。
- `--keep-temp` が指定されていれば、終了時（成功・失敗とも）に作業ディレクトリのパスを表示する。

## 13. Failure Model and Recovery Strategy

### 13.1 Failure Classes

1. `Argument / Input Failures`
   - `invalid_arguments`
   - `ipa_not_found`
   - `ipa_invalid`
   - `bundle_invalid`（Extension の Bundle ID が規則を満たさない）
   - `output_write_failed`

2. `Authentication Failures`
   - `adi_download_failed`
   - `anisette_unavailable`
   - `credentials_unavailable`
   - `login_failed`
   - `two_factor_failed`

3. `Account Resource Failures`
   - `team_not_found`
   - `device_limit_reached`
   - `device_not_found`
   - `certificate_limit_reached`
   - `certificate_not_found`
   - `app_id_quota_exceeded`
   - `app_id_not_found`
   - `ambiguous_match`
   - `profile_download_failed`
   - `apple_api_error`
   - `apple_transport_error`

4. `Device Failures`
   - `no_device_connected`
   - `multiple_devices_connected`
   - `device_not_connected`
   - `device_not_paired`
   - `device_transport_error`
   - `install_failed`

5. `Artifact Failures`
   - `signing_failed`

6. `Unexpected Failures`
   - `internal_error`（実装の不具合。`--debug` で詳細を出す）

### 13.2 Recovery Behavior

- 本ツールは自動での再試行を行わない。ただし、通信の一時的な失敗（`apple_transport_error`、
  `device_transport_error`）を有限回再試行することは許される（MAY）。その回数は Implementation-defined。
- 失敗した時点で処理を中止し、それまでに作成した Apple 側のリソースは削除しない（再実行で再利用する）。
- 作業ディレクトリは、`--keep-temp` が無ければ失敗時も削除する（MUST）。

### 13.3 Operator Intervention Points

失敗の種類ごとに、利用者が取れる対処を示す。エラーメッセージには該当する対処を含めることを RECOMMENDED とする。

- `login_failed` / `two_factor_failed`
  - `team list` でログインだけを試す。
- `anisette_unavailable` / `adi_download_failed`
  - `--anisette-server` に切り替える。または逆にローカル ADI に戻す。
- `team_not_found`
  - `team list` で ID を確かめる。
- `device_limit_reached`
  - `device list` で確認し、`device delete` で不要な登録を外す。
- `certificate_limit_reached`、または証明書の不整合が疑われる場合
  - `cert list` で確認し、`cert revoke` で不要な証明書を失効させる。
  - または `install --new-cert` で作り直す。
- `app_id_quota_exceeded`
  - `app-id list` で期限を確認して待つ。
  - または `install --strip-extensions` で必要な数を減らす。
- `signing_failed` / `install_failed`
  - `install --output` で署名だけを行い、署名と転送のどちらに問題があるかを切り分ける。
  - `--keep-temp` で署名済みの Bundle を調べる。
  - `--debug` で詳細なログを得る。
- 実行前に見通しを得たい場合
  - `install --dry-run`。

### 13.4 Irreversible Operations

次の操作は取り消せない、または取り消しても元に戻らない。

- App ID の登録: 削除しても登録枠は回復しない。
- 証明書の失効（`cert revoke`、`install --new-cert`）: その証明書で署名したアプリは起動できなくなる。
- デバイスの登録: 有料アカウントでは、削除しても年間の登録枠は回復しない。

`install` は、Section 7.4 の事前判定により、枠が足りないときに App ID を部分的に登録してはならない（MUST NOT）。

## 14. Security and Operational Safety

### 14.1 Trust Boundary Assumption

- 本ツールは、利用者自身のマシンで、利用者自身の Apple アカウントに対して使うことを想定する。
- 認証情報は Apple の認証サーバーと、指定された場合は Anisette サーバー以外に送ってはならない（MUST NOT）。
  リモート Anisette サーバーには認証情報を送らない（Anisette データの取得にだけ使う）。
- リモート Anisette サーバーは、デバイス識別子を含む Anisette データを生成する第三者である。
  ヘルプにその旨を明記することを RECOMMENDED とする。

### 14.2 Secret Handling

- パスワード、2FA コード、認証トークン、秘密鍵をログに出してはならない（MUST NOT）。`--debug` でも同様。
- `SIDELOADER_APPLE_PASSWORD` の値を表示してはならない（MUST NOT）。設定されていることだけを
  （`--debug` で）記録してよい（MAY）。
- 環境変数でパスワードを渡すと、同じユーザーの他のプロセスから読める場合がある。ヘルプにその旨を
  明記することを RECOMMENDED とする。
- CLI オプションでパスワードを受け取ってはならない（MUST NOT）。プロセス一覧に表示されるためである。

### 14.3 Filesystem Safety Requirements

- 鍵ファイルは所有者だけが読み書きできる権限（POSIX では `0600`）で作成しなければならない（MUST）。
  鍵ディレクトリは `0700` とすることを RECOMMENDED とする。
- 作業ディレクトリは OS の一時ディレクトリ配下に、推測しにくい名前で作成する（MUST）。
- IPA の展開では、`..` や絶対パスを含むエントリ、作業ディレクトリの外を指すシンボリックリンクを
  拒否しなければならない（MUST、`ipa_invalid`）。

### 14.4 Destructive Operation Safety

- `install --new-cert` と `cert revoke` は、失効させる証明書を実行前に表示しなければならない（MUST）。
- 照合が複数件に一致した削除・失効は実行してはならない（MUST NOT、`ambiguous_match`）。

## 15. Reference Algorithms (Language-Agnostic)

### 15.1 Install

```text
function install(args):
  validate_arguments(args)                          # ValidatingArguments
  bundle = prepare_bundle(args.ipa, args)           # PreparingBundle
  target = select_device(args.udid, args.mode)      # SelectingDevice

  anisette = prepare_anisette(config)               # PreparingAnisette
  session = login(anisette, resolve_credentials())  # LoggingIn
  team = select_team(session, args.team)            # SelectingTeam

  plan = build_plan(session, team, target, bundle, args)   # Planning
  if args.mode == DryRun:
    print_plan(plan)
    return plan.feasible ? 0 : 1
  if not plan.feasible:
    fail(plan.error)

  if plan.device_action == register:
    session.add_device(team, device_name(target), target.udid)  # RegisteringDevice
  identity = prepare_certificate(session, team, args.new_cert)   # PreparingCertificate
  app_ids = register_app_ids(session, team, bundle, plan)        # RegisteringAppIds
  group = configure_app_group(session, team, app_ids, bundle)    # ConfiguringAppGroup
  profiles = {}
  for app_id in app_ids:                                         # FetchingProfiles
    profiles[app_id.identifier] = session.download_team_provisioning_profile(team, app_id)
  sign(bundle, identity, profiles, config.thread_count)          # Signing

  if args.mode == Output:                                        # Delivering
    write_ipa(bundle, args.output)
  else:
    deliver(target, bundle, profiles.values())
  cleanup(args.keep_temp)                                        # CleaningUp
  print("Done.")
  return 0
```

### 15.2 Build Plan

```text
function build_plan(session, team, target, bundle, args):
  plan = {team: team}

  if target is null:
    plan.device_action = skip
  else:
    devices = session.list_devices(team)
    plan.device_action = any(d.udid == target.udid for d in devices) ? none : register

  plan.certificate_action = decide_certificate_action(session, team, args.new_cert)

  rewrite_bundle_ids(bundle, team, args.bundle_id)
  listed = session.list_app_ids(team)
  needed = [bundle] + bundle.extensions
  plan.app_ids = [{identifier: b.bundle_identifier,
                   exists: any(a.identifier == b.bundle_identifier for a in listed.app_ids)}
                  for b in needed]
  plan.app_ids_to_register = count(x for x in plan.app_ids if not x.exists)
  plan.available_quantity = listed.available_quantity

  groups = session.list_app_groups(team)
  group_id = "group." + bundle.bundle_identifier
  plan.app_group = {identifier: group_id, exists: any(g.identifier == group_id for g in groups)}

  if plan.app_ids_to_register > plan.available_quantity:
    plan.feasible = false
    plan.error = app_id_quota_exceeded(min(a.expiration_date for a in listed.app_ids))
  else:
    plan.feasible = true
  return plan
```

### 15.3 Prepare Certificate

```text
function prepare_certificate(session, team, new_cert):
  key_path = config_dir / "keys" / hex_lower(sha1(apple_id)) / "key.pem"
  sideloader_certs = [c for c in session.list_development_certs(team)
                      if c.machine_name == "Sideloader"]

  if new_cert:
    print_certificates_to_revoke(sideloader_certs)
    for c in sideloader_certs:
      session.revoke_development_cert(team, c)
    key = generate_rsa_2048()
    write_private(key_path, key)                  # mode 0600
  else if exists(key_path):
    key = read_key(key_path)
    for c in sideloader_certs:
      if public_key(c.content) == public_key(key):
        return identity(c, key)
  else:
    key = generate_rsa_2048()
    write_private(key_path, key)

  cert_id = session.submit_development_csr(team, make_csr(key))
  cert = find(session.list_development_certs(team), certificate_id == cert_id)
  return identity(cert, key)
```

### 15.4 Select Device

```text
function select_device(udid, mode):
  connected = usbmux_list_devices()
  if udid is not null:
    if udid in connected: return connected[udid]
    if mode == Install: fail(device_not_connected)
    return {udid: udid, connected: false}
  if len(connected) == 1: return connected[0]
  if len(connected) > 1: fail(multiple_devices_connected)
  if mode == Install: fail(no_device_connected)
  warn("no device connected; the profile will cover registered devices only")
  return null
```

## 16. Test and Validation Matrix

適合する実装は、本仕様の動作を確かめるテストを含めることが SHOULD である。

検証プロファイル:

- `Core Conformance`: すべての適合実装に REQUIRED な、決定的なテスト。Apple とデバイスはモックで置き換える。
- `Real Integration Profile`: 実際の Apple アカウントとデバイスを使う確認。本番利用の前に RECOMMENDED。

特に断りが無い限り、Section 16.1 から 16.6 は `Core Conformance` である。

### 16.1 CLI and Arguments

- コマンドツリー（Section 5.2）以外のコマンドを受け付けない。
- `--output` と `--dry-run` の同時指定は `invalid_arguments`。
- 存在しない IPA、ディレクトリ、拡張子が `.ipa` でないファイルは、ログイン前にエラーになる。
- 成功は終了コード 0、失敗は 1。

### 16.2 Configuration

- CLI オプションが環境変数より優先される。
- 空文字列の環境変数は未設定として扱う。
- `SIDELOADER_CONFIG_DIR` が設定ディレクトリを上書きする。
- Linux では `XDG_CONFIG_HOME` を参照する。

### 16.3 Credentials and Login

- `SIDELOADER_APPLE_ID` と `SIDELOADER_APPLE_PASSWORD` が設定されていれば入力を求めない。
- どちらか一方だけ設定されていれば、もう一方だけを求める。
- 対話入力が必要で標準入力が端末でない場合、待たずに `credentials_unavailable`。
- 2FA の `resend` で再送される。EOF で `two_factor_failed`。
- パスワードがログ（`--debug` を含む）に出ない。

### 16.4 Selection Rules

- チーム: 未指定なら最初のチーム、指定が一致しなければ `team_not_found`。
- デバイス: Section 15.4 の全分岐（モード × 接続台数 × `--udid` の有無）。
- 複数台接続で `--udid` が無ければ、どのモードでも失敗し、処理を続けない。

### 16.5 Install Pipeline

- Bundle ID の書き換え（`--bundle-id` の有無、Extension の接頭辞、規則違反時の `bundle_invalid`）。
- App ID の枠が足りないとき、1 つも登録しない。
- 各 Extension が、その Extension 自身の App ID のプロファイルで署名される。
- `--strip-extensions` で必要な App ID が 1 つになる。
- `--dry-run` で Apple 側への書き込み、デバイスへの書き込み、鍵の生成が一度も行われない。
- `--dry-run` で計画が実行不可能なら終了コード 1。
- `--new-cert` で Sideloader Certificate がすべて失効し、鍵が置き換わる。それ以外では鍵が上書きされない。
- 途中で失敗した後の再実行で、作成済みのリソースが重複して作成されない。
- `--keep-temp` の有無で作業ディレクトリが残る・残らない（失敗時を含む）。
- `--output` で書き出した IPA が、展開すると署名済みの Bundle を含む。

### 16.6 Diagnostic Commands

- 各一覧コマンドが Section 8 の項目をすべて出力する。
- `device list` がデバイス未接続でも成功する。
- `cert revoke` と `app-id delete` が、0 件で not_found、2 件以上で `ambiguous_match` になり、何も変更しない。

### 16.7 Real Integration Profile (RECOMMENDED)

- 無料アカウントと実機で、Extension を含む IPA の `install` が成功し、アプリが起動する。
- 同じ IPA の再インストールで、App ID と証明書が再利用される。
- ローカル ADI とリモート Anisette の両方でログインできる。
- 認証情報や実機が用意できない CI では省略してよい（MAY）。省略した場合は、成功ではなく省略として報告する（SHOULD）。

## 17. Implementation Checklist (Definition of Done)

### 17.1 REQUIRED for Conformance

- Section 5.2 のコマンドツリーとグローバルオプション
- Section 6 の設定の解決（CLI > 環境変数 > 対話入力 > 既定値）
- 環境変数による認証情報の受け渡し（`SIDELOADER_APPLE_ID`、`SIDELOADER_APPLE_PASSWORD`）
- エコーなしのパスワード入力と、2FA の `resend`
- ローカル ADI とリモート Anisette の両対応
- Section 7.2 の全段階と、段階名つきのエラー報告
- `install` の全オプション（`--udid`、`--team`、`--output`、`--dry-run`、`--strip-extensions`、
  `--bundle-id`、`--name`、`--new-cert`、`--keep-temp`）
- App ID の枠の事前判定（部分的な登録をしない）
- App ID ごとのプロファイル取得と署名
- Section 8 の診断用コマンド
- Section 13.1 のエラー種別と終了コード
- Section 14 の秘密情報の扱いとファイルシステムの安全性

### 17.2 RECOMMENDED Extensions (Not REQUIRED for Conformance)

- 一覧コマンドの機械可読な出力（例: `--json`）
- Wi-Fi 経由のデバイス接続
- TODO: 2FA を含むログインセッションの安全な永続化（OS のキーリング利用）

### 17.3 Operational Validation Before Production (RECOMMENDED)

- Section 16.7 の `Real Integration Profile` を、対象の各 OS（Linux、macOS、Windows）で実行する。
- 上流の Sideloader で作成した設定ディレクトリと鍵を、そのまま引き継げることを確かめる。

## Appendix A. Differences from Upstream Sideloader CLI

### A.1 Removed Commands

| コマンド | 理由 |
|---|---|
| `sign` | `install` の内部で行う。単体で使うには証明書を手元に持つ必要があり、診断用途に向かない。`install --output` で代替する |
| `trollsign` | インストールと無関係（TrollStore 用） |
| `tool list` / `tool run` | インストールと無関係（SideStore のペアリングファイル用） |
| `cert submit` | `install` が自動で行う |
| `app-id add` / `app-id download` | `install` が自動で行う |
| `device add` | `install` が自動で行う |

### A.2 Behavior Changes and Bug Fixes

1. ログインを常に行う。上流は `-i` が無いと必ず失敗していた（キーリング処理が未実装で、条件も逆だった）。`-i` は廃止する。
2. 認証情報を環境変数でも受け取る（`SIDELOADER_APPLE_ID`、`SIDELOADER_APPLE_PASSWORD`）。
3. 複数台が接続されていて `--udid` が無い場合、エラーで終了する。上流はエラーを表示した後も UDID が null のまま処理を続けていた。
4. Extension を、その Extension 自身の App ID のプロファイルで署名する。上流はすべて本体のプロファイルを取得していた。
5. Linux の設定パスで `XDG_CONFIG_HOME` を参照する。上流は存在しない `XDG_CONFIG_DIR` を参照していた。
6. 引数とデバイス選択の検証を、認証情報の入力より前に行う。
7. `install` に `--team`、`--output`、`--dry-run`、`--strip-extensions`、`--bundle-id`、`--name`、`--new-cert`、`--keep-temp` を追加する。
8. グローバルオプション `--anisette-server`（環境変数 `SIDELOADER_ANISETTE_SERVER`）を追加する。
9. `--singlethread` を廃止し、`--thread-count 1` に統一する。既定値を `uint.max` から論理 CPU 数に変える。
10. `device list` で接続中のデバイスも表示する。
11. 実行ファイル名を Implementation-defined とする（上流は `sideloader`、本リポジトリの実装は `sideload`）。
12. エラーを種別コードと段階名つきで報告する。
