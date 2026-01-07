export interface Token {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface DecodedToken {
  exp: number;
  iat: number;
  sub: string;
  permissions: string[];
  type: string;
}
