# example systemd unit files

```
cp system/* /etc/systemd/system/
cp default/* /etc/default/

systemctl daemon-reload
systemctl enable --now needroleshere.socket
systemctl enable --now needroleshere-ecs-relative.socket
```

## Tricks

The following tricks are implemented in files under system/.

### Stable `RuntimeDirectory` across multiple units

- [./systemd/needroleshere-dir.service](./systemd/needroleshere-dir.service)

As using both `DynamicUser=` and `PreserveRuntimeDirectory=` lets `RuntimeDirectory` private but we want a stable RuntimeDirectory can be shared with multiple units; Without `PreserveRuntimeDirectory=`, `RuntimeDirectory=` are subject for ereasure every time a unit starts or stops ([systemd#5394](https://github.com/systemd/systemd/issues/5394))

To workaround this problem, we need a dedicated systemd unit to hold `RuntimeDirectory`.

### Setup for `ecs-relative` mode variants

Enable and start:

- [./systemd/needroleshere-ecs-relative.socket](./systemd/needroleshere-ecs-relative.socket)

You can use this socket unit simultaneously with the primary needroleshere.socket.

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
