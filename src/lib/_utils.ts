export function makeDateWithSecondPrecision(date?: Date): Date {
  const dateWithoutMilliseconds = date ? new Date(date.getTime()) : new Date();
  dateWithoutMilliseconds.setMilliseconds(0);
  return dateWithoutMilliseconds;
}
