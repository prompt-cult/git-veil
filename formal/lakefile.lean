import Lake
open Lake DSL

package gitVeilSecurity

@[default_target]
lean_lib GitVeilSecurity where
  roots := #[`GitVeil.SecurityModel]
