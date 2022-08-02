# verdaccio-fixed-token

verdaccio middleware plugin

fork from [verdaccio-static-token](https://github.com/Eomm/verdaccio-static-token)

## how to work

any string can be use to access token

login as temporary account and it have read only permission

## configuration

```configuration.yaml
middlewares:
  fixed-token:
    - token: some_string_to_use_access_token
      user: access_as_user
    - token: second_string_to_use_access_token
      user: other_user

```

```.npmrc
//myverdaccio.example.com/:_authToken=some_string_to_use_access_token

```

## license

MIT License
