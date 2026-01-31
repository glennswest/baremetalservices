# Network Configuration Notes

## Mellanox mlx4 (ConnectX-3) with DAC Cables

Older Mellanox cards using the mlx4_en driver do not handle auto-negotiation well with DAC (Direct Attach Copper) cables. This causes link flapping:

```
mlx4_en: eth1: Link Down
mlx4_en: eth1: Link Up
mlx4_en: eth1: Link Down
mlx4_en: eth1: Link Up
```

### Solution

Disable auto-negotiation on **both** the switch port and the server NIC.

**Mikrotik RouterOS (switch side):**
```
/interface ethernet set sfp-sfpplusX auto-negotiation=no speed=10G-baseCR
```

**Linux (server side):**
```bash
ethtool -s eth1 autoneg off speed 10000 duplex full
```

### Working Configuration

| Component | Setting | Value |
|-----------|---------|-------|
| Switch | auto-negotiation | no |
| Switch | speed | 10G-baseCR |
| Server | autoneg | off |
| Server | speed | 10000 |

Both Mellanox mlx4 and Intel ixgbe NICs should have auto-negotiation disabled when the switch ports are set to fixed speed.
