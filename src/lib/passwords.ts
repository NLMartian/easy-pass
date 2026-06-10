import { randomBytes } from "./encoding";

const LOWERCASE = "abcdefghijkmnopqrstuvwxyz";
const UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?";

export type PasswordGeneratorOptions = {
  length: number;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
};

export const DEFAULT_PASSWORD_OPTIONS: PasswordGeneratorOptions = {
  length: 24,
  uppercase: true,
  digits: true,
  symbols: true,
};

export function generatePassword(options: PasswordGeneratorOptions): string {
  const groups = [LOWERCASE];
  if (options.uppercase) groups.push(UPPERCASE);
  if (options.digits) groups.push(DIGITS);
  if (options.symbols) groups.push(SYMBOLS);

  const alphabet = groups.join("");
  const characters = groups.map((group) => pickCharacter(group));
  while (characters.length < options.length) {
    characters.push(pickCharacter(alphabet));
  }

  return shuffle(characters).join("");
}

function pickCharacter(alphabet: string): string {
  const limit = Math.floor(256 / alphabet.length) * alphabet.length;
  let value = 0;
  do {
    value = randomBytes(1)[0];
  } while (value >= limit);
  return alphabet[value % alphabet.length];
}

function shuffle(values: string[]): string[] {
  const output = [...values];
  for (let index = output.length - 1; index > 0; index -= 1) {
    const swapIndex = randomBytes(1)[0] % (index + 1);
    [output[index], output[swapIndex]] = [output[swapIndex], output[index]];
  }
  return output;
}
