#!/usr/bin/env bash
# RedAI 发版助手：把「容易漏的那几步」做成硬校验，然后打 tag 推送。
#
# 用法：
#   ./scripts/release.sh 0.4.85
#
# 它会做三件事：
#   1. 校验 CHANGELOG.md 里已有 `## [0.4.85]` 段（CI 缺这段会直接拒绝发布）；
#   2. 校验工作区干净、tag 不存在、当前在 main 分支；
#   3. 打 annotated tag 并推送（推送 tag 即触发 .github/workflows/release.yml）。
#
# 为什么把 CHANGELOG 校验放在前面：Release 的说明文字是从 CHANGELOG 对应段落
# 抽取的（release.yml 里找不到 `## [版本]` 会 exit 1）。先本地拦住，比等 CI 跑完
# 三个平台再失败划算得多。
set -euo pipefail

cd "$(cd "$(dirname "$0")/.." && pwd)"

die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }

VER="${1:-}"
[ -n "$VER" ] || die "用法: ./scripts/release.sh <版本号>，例如 0.4.85"
VER="${VER#v}"

case "$VER" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "版本号格式应为 X.Y.Z，收到: $VER" ;;
esac

TAG="v$VER"

[ -f CHANGELOG.md ] || die "找不到 CHANGELOG.md"
if ! grep -q "^## \[$VER\]" CHANGELOG.md; then
  die "CHANGELOG.md 缺少 '## [$VER]' 段。CI 会因此拒绝发布空说明的 Release。
     先在 CHANGELOG 顶部补一段再重跑。"
fi
ok "CHANGELOG 含 [$VER] 段"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" = "main" ] || die "当前在 $BRANCH 分支，发版请在 main 上"

if [ -n "$(git status --porcelain)" ]; then
  die "工作区不干净，先提交或清理：
$(git status --short | head -10)"
fi
ok "工作区干净"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  die "tag $TAG 已存在。要重发请先删：git tag -d $TAG && git push origin :refs/tags/$TAG"
fi

if ! git remote get-url origin >/dev/null 2>&1; then
  die "未配置 origin 远程仓库"
fi

info "即将：打 tag $TAG 并推送 main + tag 到 $(git remote get-url origin)"
info "推送后 GitHub Actions 会自动构建 linux/darwin × amd64/arm64、"
info "生成 SHA256SUMS、创建 Release，并推送镜像 ghcr.io/backslion/redai"
read -r -p "继续？[y/N] " ans
case "$ans" in
  y|Y) ;;
  *) die "已取消" ;;
esac

git tag -a "$TAG" -m "RedAI $TAG"
ok "已打 tag $TAG"

git push origin main
git push origin "$TAG"
ok "已推送。发布进度：$(git remote get-url origin | sed 's#\.git$##')/actions"
