// A single match is no narrowing, so only an ambiguous sync gets a note.
export function githubTeamCandidatesNote(count?: number | null, teamName?: string | null): string | null {
  if (!count || count < 2) return null;
  return teamName ? `${count} teams matched, using ${teamName}` : `${count} teams matched`;
}
