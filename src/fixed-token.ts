import { Application, NextFunction, Request, Response } from "express";
import {
  IPluginMiddleware,
  IBasicAuth,
  IPluginAuth,
  Security,
  RemoteUser,
  JWTSignOptions,
  AllowAccess,
  AuthAccessCallback,
  PackageAccess,
  Callback,
} from "@verdaccio/types";
import { IConfig, PluginConfig, pluginName } from "./config";

export interface IAuth extends IBasicAuth<IConfig> {
  config: IConfig;
  apiJWTmiddleware(): NextFunction;
  jwtEncrypt(user: RemoteUser, signOptions: JWTSignOptions): Promise<string>;
  webUIJWTmiddleware(): NextFunction;
}

const TIME_EXPIRATION_7D = "7d" as const;

export class FixedToken
  implements IPluginMiddleware<IConfig>, IPluginAuth<IConfig>
{
  security: Security;
  allowUsers: PluginConfig[];
  auth: IAuth | undefined;

  constructor(readonly config: IConfig) {
    this.security = config.security;
    this.allowUsers = config.middlewares[pluginName];
  }

  authenticate(_user: string, _password: string, cb: Callback) {
    console.log("called authenticate");
    cb(null, null);
  }

  allow_access(
    user: RemoteUser,
    _pkg: AllowAccess & PackageAccess,
    cb: AuthAccessCallback
  ) {
    console.log("called allow_access");
    const found = this.allowUsers.find((e) => e.user === user.name);
    if (found) {
      // console.log("allow access");
      cb(null, true);
    } else {
      cb(null, false);
    }
  }

  register_middlewares(app: Application, auth: IAuth) {
    this.auth = auth;

    app.use(this.hookToken);
  }

  public hookToken = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    const authorization = req.headers?.["authorization"];
    if (authorization && authorization !== "") {
      const found = this.allowUsers.find(
        (e) => `Bearer ${e.token}` === authorization
      );
      if (found) {
        // console.log(`Applying custom token for ${found.user}`);
        const payload: RemoteUser = {
          name: found.user,
          real_groups: [],
          groups: [],
        };
        const sign = this.security?.api?.jwt?.sign || {
          expiresIn: TIME_EXPIRATION_7D,
        };
        if (this.auth) {
          const ret = await this.auth.jwtEncrypt(payload, sign);
          req.headers["authorization"] = `Bearer ${ret}`;
        }
      }
    }
    next();
  };
}
