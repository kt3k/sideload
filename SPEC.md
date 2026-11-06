# sideload CLI 仕様（Sideloader CLI のサブセット移植）

元実装: [Dadoum/Sideloader](https://github.com/Dadoum/Sideloader) `frontends/cli`（commit `ed89e28`）

## 方針

- 目的は **`install` コマンド**（IPA を iOS デバイスへサイドロードする）。
- それ以外は、`install` が失敗したときに **原因を特定・解消するためのデバッグ用コマンド** だけを残す。
- 元実装の既知の不具合は移植時に修正する（末尾「元実装からの変更点」）。

## コマンド一覧

```
sideload [グローバルオプション] <コマンド>

sideload install <ipa>            IPA をデバイスにインストール

# デバッグ用
sideload team list                ログイン確認・チーム ID 確認
sideload device list              登録済みデバイス / 接続中デバイス
sideload device delete <id>       登録済みデバイスの削除
sideload cert list                開発証明書一覧
sideload cert revoke <serial>     開発証明書の失効
sideload app-id list              App ID 一覧と残り枠
sideload app-id delete <bundleId> App ID の削除

sideload version                  バージョン表示（不具合報告用）
```

### 元実装から削除するもの

| コマンド | 削除理由 |
|---|---|
| `sign` | install 内部で行う。単体で使うには証明書を手元に持つ必要があり、デバッグ用途に向かない |
| `trollsign` | install と無関係（TrollStore 用） |
| `tool list` / `tool run` | install と無関係（SideStore のペアリングファイル用） |
| `cert submit` | install が自動で CSR を提出する |
| `app-id add` / `app-id download` | install が自動で行う |
| `device add` | install が自動で行う |

## グローバルオプション

| オプション | 既定値 | 説明 |
|---|---|---|
| `-d`, `--debug` | off | ログレベルを TRACE にする。install 失敗時の一次調査手段 |
| `--thread-count <N>` | CPU コア数 | 署名の並列数。`1` を指定すると元実装の `--singlethread` と同じ動作 |
| `--anisette-server <URL>` | なし | Anisette をリモートサーバー（anisette-v3 互換）から取得する。指定しなければローカルの ADI を使う |

### 環境変数

| 変数 | 説明 |
|---|---|
| `SIDELOADER_CONFIG_DIR` | 設定ディレクトリを上書きする |
| `SIDELOADER_ANISETTE_SERVER` | `--anisette-server` の既定値。オプションの指定が優先される |

## 共通の動作

### 設定ディレクトリ

| OS | パス |
|---|---|
| Linux | `${XDG_CONFIG_HOME:-~/.config}/Sideloader` |
| macOS | `~/Library/Preferences/Sideloader` |
| Windows | `%AppData%\Sideloader` |

元実装と同じ場所を使い、既存の鍵を引き継げるようにする。

```
<config>/
  lib/libstoreservicescore.so   ADI ライブラリ（無ければ自動ダウンロード）
  lib/libCoreADI.so
  keys/<sha1(AppleID) の16進小文字>/key.pem   署名用 RSA 2048 秘密鍵
```

### ログイン（`version` 以外の全コマンド）

1. Anisette を準備する。
   - `--anisette-server` の指定なし: ローカルの ADI を初期化する。ライブラリが無ければ進捗（%）を表示しながらダウンロードする。
   - 指定あり: そのサーバーを使う。ADI ライブラリはダウンロードしない。サーバーに接続できなければエラーにする。
2. Apple ID を標準入力から読み、パスワードをエコーなしで読む。
3. 2FA コードの入力を求める。`resend` と入力すると再送する。
4. ログインできなければエラーを表示して終了コード 1 で終わる。

認証情報は保存しない（キーリング対応は対象外）。

### チームの選択（`--team <TeamID>`）

- 指定なし: アカウントの最初のチームを使う。
- 指定あり: ID が一致するチームを使う。無ければ `No matching team found.` を表示してエラーにする。

### 接続デバイスの選択（`--udid <UDID>`）

- 指定なし: 接続中が 1 台ならそれを使う。0 台なら `No device connected.`、2 台以上なら `Multiple devices are connected. Please select one with --udid.` を表示してエラーにする。
- 指定あり: その UDID のデバイスを使う。接続されていなければエラーにする。

### 終了コード

| コード | 意味 |
|---|---|
| 0 | 成功 |
| 1 | 失敗（引数エラー、ログイン失敗、API エラー、予期しない例外を含む） |

例外は `<種類>: <メッセージ>` の形で表示する。詳細（スタックトレースや HTTP のやりとり）は `--debug` 指定時だけ表示する。

---

## `install <ipa>`

| 引数・オプション | 必須 | 説明 |
|---|---|---|
| `<ipa>` | ○ | IPA ファイル。存在し、通常ファイルで、拡張子が `.ipa` でなければエラー |
| `--udid <UDID>` | | 対象デバイス |
| `--team <TeamID>` | | 使用するチーム（元実装には無く、追加する） |

#### 動作モード（`--output` と `--dry-run` は同時に指定できない）

| オプション | 説明 |
|---|---|
| `-o`, `--output <path>` | 署名までを行い、署名済み IPA を `<path>` に書き出す。デバイスへのインストールはしない（ステップ 8 を省略）。署名の問題と転送の問題を切り分けるのに使う |
| `--dry-run` | Apple 側もデバイスも一切変更しない。ログインと読み取り系の API 呼び出しだけを行い、実行した場合の計画を表示する（後述） |

#### アプリの加工

| オプション | 説明 |
|---|---|
| `--strip-extensions` | `PlugIns/*.appex` と `Watch/` を削除してから処理する。必要な App ID は本体の 1 つだけになる |
| `--bundle-id <id>` | 本体の Bundle ID に `<id>` をそのまま使う（`.<TeamID>` は付けない）。Extension は元の接頭辞を `<id>` に置き換える |
| `--name <name>` | `CFBundleDisplayName` を `<name>` に書き換える |

#### 証明書

| オプション | 説明 |
|---|---|
| `--new-cert` | ステップ 3 で既存の証明書を再利用しない。マシン名が `Sideloader` の証明書をすべて失効させ、ローカルの `key.pem` を作り直して CSR を提出し直す。**失効させた証明書で署名済みのアプリは起動できなくなる**ため、実行前に失効させる証明書を表示する |

#### デバッグ

| オプション | 説明 |
|---|---|
| `--keep-temp` | 作業ディレクトリ（展開・加工・署名した `.app`）を削除せず、終了時にパスを表示する。失敗した場合も残す |

### 処理手順（進捗バーにステップ名を表示）

| # | ステップ | 内容 | 主な失敗原因 → 使うデバッグコマンド |
|---|---|---|---|
| 0 | ログイン | 共通処理 | 認証失敗・2FA → `team list`、ADI が動かない → `--anisette-server` |
| 1 | 展開・加工 | IPA を作業ディレクトリに展開し、`--strip-extensions` と `--name` を適用する | `--keep-temp` |
| 2 | チーム取得 | `--team` に従う | → `team list` |
| 3 | デバイス登録 | 対象デバイスの UDID が未登録なら、lockdown から端末名を取得して登録する。`--output` 指定時にデバイスが接続されておらず `--udid` も無い場合は、警告を出して省略する（プロファイルの対象は登録済みデバイスだけになる） | 登録上限 → `device list` / `device delete` |
| 4 | 証明書の準備 | `keys/.../key.pem` があり、Apple 側にマシン名が `Sideloader` で公開鍵が一致する証明書があれば再利用する。無ければ鍵を生成（または既存の鍵を使用）して CSR を提出する。`--new-cert` 指定時の動作は上記のとおり | 証明書の上限 → `cert list` / `cert revoke` / `--new-cert` |
| 5 | App ID 作成 | Bundle ID を `<元のID>.<TeamID>`（`--bundle-id` 指定時はその値）に書き換える。Extension も同じ接頭辞で書き換える。不足する App ID の数が残り枠を超える場合は **1 つも登録せず** に中断し、最も早く期限が切れる日時を表示する | 枠不足 → `app-id list` / `--strip-extensions`（`app-id delete` しても枠は戻らない） |
| 6 | App Group | 全 App ID で App Group を有効にし、`group.<mainAppId>` を作成または再利用する。SideStore（`com.SideStore.SideStore`）の場合は `ALTAppGroups` も設定する | `--debug` |
| 7 | プロファイル取得 | 各 App ID に App Group を割り当て、**その App ID の**プロビジョニングプロファイルを取得する | `--debug` |
| 8 | 署名 | 本体と Extension を署名する（`--thread-count` に従って並列化） | `--debug` / `--keep-temp` |
| 9 | インストール | AFC で `PublicStaging/<App名>.app` へ転送し、installation_proxy に `PackageType=Developer` を指定してインストールさせる。`--output` 指定時はこのステップの代わりに IPA を書き出す | `--output` で切り分け、デバイス側の信頼設定 |

成功したら `Done.` を表示して終了コード 0 で終わる。

### `--dry-run` の出力

ステップ 1 は作業ディレクトリ内でだけ行い、ステップ 2 以降は読み取り系 API だけを呼ぶ。次の内容を表示する。

```
Team:         <name> (<teamId>)
Device:       <udid> (registered | will be registered)
Certificate:  reuse <serial> | will create new | will revoke <serial>, ... and create new
App IDs:      need N, already registered M, will register K (available: A / max: X)
  - <bundleId> (exists | new)
App Group:    group.<mainAppId> (exists | new)
Result:       OK | NG: <理由>
```

結果が NG の場合（App ID の枠不足、デバイスの登録上限など）は終了コード 1 で終わる。

---

## デバッグ用コマンド

`team list` 以外は `--team` を受け付ける。

### `team list`
ログインできるかを確認し、`--team` に指定できる ID を調べるためのコマンド。
```
Teams:
 - `<name>`, with ID `<teamId>`.
```

### `device list [--udid <UDID>]`
アカウントに登録されているデバイスを表示する。接続中のデバイスには `(connected)` を付ける。デバイスが接続されていなくても登録一覧は表示する。
```
You have N devices registered.
 - Device `<name>` of UDID `<udid>` with the identifier `<deviceId>` (connected)
Connected devices not registered:
 - `<udid>`
```

### `device delete <deviceId>`
登録を解除する。引数は UDID ではなく、`device list` に表示される identifier。

### `cert list`
```
You have N certificates registered.
 - `<name>` with the serial number `<serial>`, from the machine named `<machineName>`.
```
install が作成した証明書は machineName が `Sideloader`。

### `cert revoke <serialNumber>`
一致する証明書が 0 件ならエラーにする。2 件以上一致した場合も安全のため中断する。

### `app-id list`
```
You have <available> App IDs available out of the <max> you have at your disposal.
 - `<identifier>` for the app `<name>`, expiring on <date>.
```

### `app-id delete <identifier>`
一致判定は `cert revoke` と同じ。削除しても登録枠は回復しないことをヘルプに明記する。

### `version`
バージョン文字列を表示する。ログイン不要。

---

## 元実装からの変更点（不具合修正を含む）

1. **ログインが常に対話式になる。** 元実装は `-i` が無いと必ず失敗した（キーリング処理が未実装のうえ条件が逆だった）。`-i` は廃止する。
2. **`install` で複数台が接続されているとき、`--udid` が無ければエラーで終了する。** 元実装はエラーを表示した後も udid が null のまま処理を続けていた。
3. **プロファイルを App ID ごとに取得する。** 元実装は Extension 分も含め、すべてメインアプリのプロファイルを取得していた。
4. **Linux の設定パスで `XDG_CONFIG_HOME` を参照する。** 元実装は存在しない `XDG_CONFIG_DIR` を参照していた。
5. **`install` に `--team` を追加する。** 元実装は常に最初のチームを使っていた。
6. **`--singlethread` を廃止し `--thread-count 1` に統一する。** `--thread-count` の既定値は `uint.max` から CPU コア数に変える。
7. **`device list` で接続中のデバイスも表示する**（登録漏れの調査用）。
8. コマンド名を `sideloader` から `sideload` に変える（リポジトリ名に合わせる。要確認）。
9. `install` にオプションを追加する: `--output`, `--dry-run`, `--keep-temp`, `--strip-extensions`, `--bundle-id`, `--name`, `--new-cert`。
10. グローバルオプション `--anisette-server` を追加する（リモートの Anisette サーバーに対応）。

## 未決事項

- [ ] 非対話環境（CI など）向けに、環境変数で Apple ID とパスワードを渡せるようにするか
- [ ] コマンド名は `sideload` と `sideloader` のどちらにするか
