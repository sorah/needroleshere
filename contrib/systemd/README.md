# example systemd unit files

```
cp system/* /etc/systemd/system/
cp default/* /etc/default/
```

## Tricks

The following tricks are implemented in files under system/.

### Stable `RuntimeDirectory` across multiple units

- [./systemd/needroleshere-dir.service](./systemd/needroleshere-dir.service)

As using both `DynamicUser=` and `PreserveRuntimeDirectory=` lets `RuntimeDirectory` private but we want a stable RuntimeDirectory can be shared with multiple units; Without `PreserveRuntimeDirectory=`, `RuntimeDirectory=` are subject for ereasure every time a unit starts or stops ([systemd#5394](https://github.com/systemd/systemd/issues/5394))

To workaround this problem, we need a dedicated systemd unit to hold `RuntimeDirectory`.

### Setup for `ecs-relative` mode variants

Reconfigure your socket unit like the following. You need to update `--url` if you're also using `ecs-full` mode variants.

```systemd
# /etc/systemd/system/needroleshere.socket
[Socket]
ListenStream=169.254.170.2:80
FreeBind=yes

ExecStartPre=-/bin/ip address add 169.254.170.2/32 dev lo

IPAddressAllow=localhost
IPAddressAllow=169.254.170.2/32
IPAddressDeny=any
```

### Utilizing systemd unit template

- [./systemd/needroleshere-bind@.service](./systemd/needroleshere-bind@.service)

It is possible to use systemd unit template for the `needroleshere bind` service unit explained at README.

then `systemctl enable needroleshere-bind@somethingawesome.service` to pair with `somethingawesome.service`. 

## Tips

### Giving a permission to DynamicUser

the systemd units utilize `DynamicUser=`. As long as you keep same User=/Group= and a username specified to User= does not exist, you can use a dynamically allocated user with a static gid.

```systemd
DynamicUser=yes
User=needroleshere
Group=certificateallowed
```
