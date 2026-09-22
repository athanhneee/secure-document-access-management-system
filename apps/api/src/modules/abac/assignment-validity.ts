export function isAssignmentActive(
  assignment: { validFrom: Date; validTo: Date | null },
  at: Date,
): boolean {
  return assignment.validFrom <= at && (assignment.validTo === null || assignment.validTo > at);
}
