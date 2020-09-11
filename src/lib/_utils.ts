export function makeDateWithSecondPrecision(date?: Date): Date {
  const dateWithoutMilliseconds = date ? new Date(date.getTime()) : new Date();
  dateWithoutMilliseconds.setMilliseconds(0);
  return dateWithoutMilliseconds;
}

/**
 * Try/catch block as a expression, a la Kotlin.
 *
 * @param tryCallback
 * @param catchCallback
 *
 * To avoid using `let`.
 */
export async function tryCatchAsync<T>(
  tryCallback: () => Promise<T>,
  catchCallback: (error: Error) => Error,
): Promise<T> {
  // tslint:disable-next-line:no-let
  let result: T;
  try {
    result = await tryCallback();
  } catch (error) {
    throw catchCallback(error);
  }
  return result;
}
