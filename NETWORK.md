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

Disable auto-negotiation on the switch port and set a fixed speed:

**Mikrotik RouterOS:**
```
/interface ethernet set sfp-sfpplusX auto-negotiation=no speed=10G-baseCR
```

### Working Configuration

| Setting | Value |
|---------|-------|
| auto-negotiation | no |
| speed | 10G-baseCR |

The Intel ixgbe (10Gbps) NICs work fine with auto-negotiation enabled.
