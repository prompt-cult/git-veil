import GitVeil.V018

open GitVeil.SecurityModel

private def bit (b : Bool) : String := if b then "1" else "0"

private def relation : Rel3 → String
  | .below => "below"
  | .equal => "equal"
  | .above => "above"

private def verdict : FreshnessVerdict → String
  | .accept => "accept"
  | .unsignedEmptyRollback => "unsigned-empty-rollback"
  | .versionRollback => "version-rollback"
  | .equalVersionFork => "equal-version-fork"

def main : IO Unit := do
  for c in allFreshnessCells do
    IO.println s!"freshness {bit c.signed} {bit c.empty} {bit c.hasBaseline} {relation c.rel} {bit c.digestDiff} {verdict (freshnessVerdictV18 c)}"
  for c in allRotateCells do
    IO.println s!"rotate {bit c.securityOk} {bit c.nonEmptyRing} {bit c.stampMatch} {bit c.noOrphans} {bit c.indexOnly} {bit (rotateGateV18 c)}"
  for c in allSecurityCells do
    IO.println s!"security {bit c.pinPresent} {bit c.pinMatch} {bit c.sigOk} {bit c.freshOk} {bit c.permsSafe} {bit c.bypass} {bit (cellSecurity c)}"
