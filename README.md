# Scanner de Rede Modular (macOS)

![Versão](https://img.shields.io/badge/vers%C3%A3o-4.0-blue)

Scanner de rede profissional e modular, otimizado para macOS (especialmente Apple Silicon M3 com 8GB RAM). Realiza detecção automática da rede, varredura detalhada de dispositivos, identificação por MAC (OUI), e gera relatórios completos em TXT e JSON.

## Recursos

- Detecção automática da configuração de rede (interface, gateway, IP, máscara, DNS)
- Descoberta de dispositivos ativos (ping sweep)
- Análise detalhada de cada dispositivo (MAC, fabricante, tipo, portas, serviços, SO)
- Identificação inteligente por OUI (MAC address)
- Relatórios em TXT e JSON
- Otimizado para performance em macOS
- Saída colorida e barra de progresso (tqdm)

## Requisitos

- **macOS** (Apple Silicon recomendado)
- **Python >= 3.7** (testado com 3.13)
- **[nmap](https://nmap.org/)** (>= 7.80)
- **[uv](https://github.com/astral-sh/uv)** para gerenciamento de dependências Python
- **colorama** e **tqdm** (instalados via uv)

## Instalação

### 1. Instale o nmap (via Homebrew)

```sh
brew install nmap
```

### 2. Instale o uv (se ainda não tiver)

```sh
brew install uv
```

### 3. Instale as dependências Python

```sh
uv pip install colorama tqdm
```

> **Dica:** O projeto já inclui um `pyproject.toml`. Você pode instalar todas as dependências listadas nele com:
>
> ```sh
> uv pip install -r requirements.txt  # (se requirements.txt existir)
> # ou instale manualmente:
> uv pip install colorama tqdm
> ```

## Uso

> **Atenção:** Execute apenas em redes próprias ou com autorização!

### Execução padrão

```sh
python3 main.py
```

### Execução com privilégios root (recomendado para scans completos)

```sh
sudo python3 main.py
```

### Exemplo de saída

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SCANNER DE REDE MODULAR v4.0                             ║
║                        Especializado para macOS M3                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  • Detecção automática de rede                                              ║
║  • Análise detalhada de dispositivos                                        ║
║  • Identificação por MAC address (OUI)                                      ║
║  • Scanning otimizado para 8GB RAM                                          ║
║  • Relatórios em TXT e JSON                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Relatórios

- Os relatórios são salvos na pasta `network_scan_results/`.
- Dois formatos: `.txt` (humano) e `.json` (automatização).

## Solução de Problemas

### Erro: `dnet: Failed to open device en0`

- Certifique-se de que a interface de rede está ativa:
  ```sh
  sudo ifconfig en0 up
  ```
- Execute o script como root:
  ```sh
  sudo python3 main.py
  ```
- Se persistir, tente reiniciar o adaptador de rede:
  ```sh
  sudo ifconfig en0 down && sudo ifconfig en0 up
  ```

### Permissões

- Para varreduras SYN e detecção de MAC, é necessário executar como root.
- O script avisa se não estiver com privilégios suficientes.

### Dependências Python

- Se aparecer erro de dependência, instale manualmente:
  ```sh
  uv pip install colorama tqdm
  ```

### Nmap não encontrado

- Instale via Homebrew:
  ```sh
  brew install nmap
  ```

## Estrutura do Projeto

- `main.py`: Script principal, modularizado em classes.
- `pyproject.toml`: Configuração de dependências Python.
- `network_scan_results/`: Relatórios gerados.

## Licença

Uso educacional e profissional autorizado apenas em redes próprias ou com permissão explícita.

---

Desenvolvido por: Scanner de Rede Profissional
