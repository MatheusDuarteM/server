<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
ini_set('error_log', 'php_errors.log');

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');

// Função centralizada para retornar JSON
function respondeJson($status, $mensagem, $dados = [])
{
    $response = ['status' => $status, 'message' => $mensagem, 'data' => $dados];
    echo json_encode($response);
    exit; // Certifique-se de que você quer sair após cada resposta
}


// Função de conexão com o banco
function abreConexaoBD()
{
    $nomeServidor = "localhost";
    $nomeusuarios = "root";
    $senhaAcesso = "";
    $nomeBanco = "cadastro";

    try {
        $conn = new PDO("mysql:host=$nomeServidor;dbname=$nomeBanco", $nomeusuarios, $senhaAcesso);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $conn;
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Falha ao iniciar conexão com o BD: ' . $e->getMessage()]);
        exit();
    }
}

function buscaResumoPatrimonio()
{
    $conn = abreConexaoBD();

    try {
        // Consultar o total de patrimônio descartado
        $queryDescartado = "SELECT COUNT(*) AS total FROM patrimonio WHERE status = 'descartado'";
        $stmtDescartado = $conn->query($queryDescartado);
        $descartado = (int)$stmtDescartado->fetch(PDO::FETCH_ASSOC)['total'];  // Garantir que seja um inteiro

        // Consultar o total de patrimônio emprestado
        $queryEmprestado = "SELECT COUNT(*) AS total FROM patrimonio WHERE status = 'Emprestado'";
        $stmtEmprestado = $conn->query($queryEmprestado);
        $emprestado = (int)$stmtEmprestado->fetch(PDO::FETCH_ASSOC)['total'];  // Garantir que seja um inteiro

        // Consultar o total de patrimônio em uso
        $queryUsando = "SELECT COUNT(*) AS total FROM patrimonio WHERE status = 'Usando'";
        $stmtUsando = $conn->query($queryUsando);
        $usando = (int)$stmtUsando->fetch(PDO::FETCH_ASSOC)['total'];  // Garantir que seja um inteiro

        // Retornar os dados em formato JSON
        echo json_encode([
            'status' => 'success',
            'data' => [
                'descartado' => (string)$descartado, // Garantir que seja retornado como string
                'Emprestado' => (string)$emprestado, // Garantir que seja retornado como string
                'Usando' => (string)$usando, // Garantir que seja retornado como string
            ]
        ]);
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao buscar resumo do patrimônio: ' . $e->getMessage()]);
    }
}



function validaUsuario($usuario, $senha)
{
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM usuario WHERE usuario = :usuario AND senha = :senha";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':usuario', $usuario);
    $stmt->bindParam(':senha', $senha);
    $stmt->execute();

    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function logar($usuario, $senha)
{
    $usuarioValidado = validaUsuario($usuario, $senha);

    if ($usuarioValidado) {
        echo json_encode(['status' => 'success', 'message' => 'Login bem-sucedido!', 'usuario' => $usuarioValidado]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Usuário ou senha inválidos.']);
    }
}

function criaUsuarios($usuario, $senha)
{
    $conn = abreConexaoBD();
    $sql = "INSERT INTO usuario (usuario, senha) VALUES (:usuario, :senha)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':usuario', $usuario);
    $stmt->bindParam(':senha', $senha);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Registro criado com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro no processo de criação.']);
    }
}
function inserirDados($marca, $modelo, $cor, $codigo, $data, $fotoBase64, $status, $setor, $descricao)
{
    // Verifique se os dados necessários estão presentes
    if (empty($marca) || empty($modelo) || empty($cor) || empty($codigo) || empty($data) || empty($status) || empty($setor) || empty($descricao) || empty($fotoBase64)) {
        echo json_encode(['status' => 'error', 'message' => 'Alguns campos estão ausentes ou vazios.']);
        return;
    }

    $conn = abreConexaoBD();
    $fotoNome = uniqid() . '.png';
    $fotoCaminho = 'imagens/' . $fotoNome;

    // Cria o diretório de imagens, se necessário
    if (!file_exists('imagens')) {
        mkdir('imagens', 0777, true);
    }

    // Valida a imagem e grava o arquivo
    if ($fotoBase64 && base64_decode($fotoBase64, true) !== false) {
        file_put_contents($fotoCaminho, base64_decode($fotoBase64));
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Imagem inválida']);
        return;
    }

    // SQL de inserção
    $sql = "INSERT INTO patrimonio (marca, modelo, cor, codigo, data, imagem, status, setor, descricao) 
            VALUES (:marca, :modelo, :cor, :codigo, :data, :imagem, :status, :setor, :descricao)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':marca', $marca);
    $stmt->bindParam(':modelo', $modelo);
    $stmt->bindParam(':cor', $cor);
    $stmt->bindParam(':codigo', $codigo);
    $stmt->bindParam(':data', $data);
    $stmt->bindParam(':imagem', $fotoCaminho);
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':setor', $setor);
    $stmt->bindParam(':descricao', $descricao);

    try {
        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => 'Dados inseridos com sucesso.']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Erro ao inserir os dados.']);
        }
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao inserir os dados: ' . $e->getMessage()]);
    }
}

function inserirModelo($modelo, $cor, $imagemModelo, $descricao)
{
    // 1. Verificação e Sanitização dos Dados
    if (empty($modelo) || empty($cor) || empty($descricao) || empty($imagemModelo)) {
        respondeJson('error', 'Alguns campos estão ausentes ou vazios.');
    }

    // 2. Decodificação e Validação da Imagem
    $imagemData = base64_decode($imagemModelo, true);
    if ($imagemData === false) {
        respondeJson('error', 'Imagem inválida (base64).');
    }

    $conn = abreConexaoBD();

    // SQL de inserção
    $sql = "INSERT INTO inserirmodelo (modelo, cor, imagemModelo, descricao) 
            VALUES (:modelo, :cor, :imagemModelo, :descricao)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':modelo', $modelo);
    $stmt->bindParam(':cor', $cor);
    $stmt->bindParam(':imagemModelo', $imagemData, PDO::PARAM_LOB); // Salvar os dados binários
    $stmt->bindParam(':descricao', $descricao);

    try {
        if ($stmt->execute()) {
            respondeJson('success', 'Dados inseridos com sucesso.');
        } else {
            error_log("Erro ao inserir dados: " . print_r($stmt->errorInfo(), true));
            respondeJson('error', 'Erro ao inserir os dados.');
        }
    } catch (PDOException $e) {
        error_log("Erro ao inserir dados2: " . $e->getMessage());
        respondeJson('error', 'Erro ao inserir os dados: ' . $e->getMessage());
    }
}

function listarModelos()
{
    $conn = abreConexaoBD();
    $sql = "SELECT modelo FROM inserirmodelo";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $modelos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    error_log("listarModelos: SQL = " . $sql); // Log da query
    error_log("listarModelos: Erro SQL = " . print_r($stmt->errorInfo(), true));
    error_log("listarModelos: Modelos = " . print_r($modelos, true)); // Log dos modelos

    if ($modelos) {
        respondeJson('success', 'Modelos listados com sucesso.', ['data' => $modelos]);
    } else {
        respondeJson('error', 'Nenhum modelo encontrado.');
    }
}

function buscarModelo($modelo)
{
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM inserirmodelo WHERE modelo = :modelo";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':modelo', $modelo);
    $stmt->execute();
    $modeloData = $stmt->fetch(PDO::FETCH_ASSOC);

    error_log("buscarModelo: Modelo = " . $modelo);
    error_log("buscarModelo: SQL = " . $sql);
    error_log("buscarModelo: ModeloData = " . print_r($modeloData, true));

    if ($modeloData) {
        // Codifica a imagem em Base64 antes de incluir no JSON
        if (!empty($modeloData['imagemModelo'])) {
            $modeloData['imagemModelo'] = base64_encode($modeloData['imagemModelo']);
        }
        respondeJson('success', 'Dados do modelo carregados com sucesso.', ['data' => $modeloData]);
    } else {
        respondeJson('error', 'Modelo não encontrado.');
    }
}
function listaTodosProdutos()
{
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM patrimonio";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $produtos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['status' => 'success', 'produtos' => $produtos ?: []]);
}

function alteraPatrimonio($data)
{
    $conn = abreConexaoBD();
    $id = $data['id'] ?? null; // Verifica se o ID foi fornecido
    $marca = $data['marca'];
    $modelo = $data['modelo'];
    $cor = $data['cor'];
    $codigo = $data['codigo'];
    $dataPatrimonio = $data['data'];
    $status = $data['status'];
    $setor = $data['setor'];
    $descricao = $data['descricao'];
    $fotoBase64 = $data['foto'] ?? null; // Suporte para imagem ao atualizar

    // Verificar se o ID está definido e não é vazio
    if (empty($id)) {
        echo json_encode(['status' => 'error', 'message' => 'ID do patrimônio não fornecido.']);
        return;
    }

    // Verificar se o patrimônio existe
    $sql = "SELECT * FROM patrimonio WHERE id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $id);
    $stmt->execute();
    $patrimonioExistente = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$patrimonioExistente) {
        echo json_encode(['status' => 'error', 'message' => 'Patrimônio não encontrado.']);
        return;
    }

    // Montar a consulta SQL
    $sql = "UPDATE patrimonio SET 
                marca = :marca, 
                modelo = :modelo, 
                cor = :cor, 
                codigo = :codigo, 
                data = :data, 
                status = :status, 
                setor = :setor, 
                descricao = :descricao" .
        (!empty($fotoBase64) ? ", imagem = :imagem" : "") .
        " WHERE id = :id";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':marca', $marca);
    $stmt->bindParam(':modelo', $modelo);
    $stmt->bindParam(':cor', $cor);
    $stmt->bindParam(':codigo', $codigo);
    $stmt->bindParam(':data', $dataPatrimonio);
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':setor', $setor);
    $stmt->bindParam(':descricao', $descricao);
    $stmt->bindParam(':id', $id);

    // Se houver uma imagem, salvar a imagem e incluir no banco
    if (!empty($fotoBase64)) {
        $fotoNome = uniqid() . '.png';
        $fotoCaminho = 'imagens/' . $fotoNome;
        file_put_contents($fotoCaminho, base64_decode($fotoBase64));
        $stmt->bindParam(':imagem', $fotoCaminho);
    }

    // Executar a consulta
    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Dados atualizados com sucesso.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao atualizar dados.']);
    }
}

function apagaDadosPatrimonio($id)
{
    $conn = abreConexaoBD();
    $sql = "DELETE FROM patrimonio WHERE id = :id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':id', $id);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Patrimônio excluído com sucesso.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao excluir o patrimônio.']);
    }
}
function descartarProduto($id)
{
    $conn = abreConexaoBD();

    try {
        // Atualiza o status do produto para "descartado"
        $sql = "UPDATE patrimonio SET status = 'descartado' WHERE id = :id";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':id', $id, PDO::PARAM_INT);

        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => 'Produto excluido com Sucesso']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Erro ao atualizar o status do produto']);
        }
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erro: ' . $e->getMessage()]);
    }
}

// Funções de manipulação de marca
function inserirMarca($nome, $status = 'ativo') // Definindo 'ativo' como padrão
{
    if (empty($nome)) {
        echo json_encode([
            'status' => 'error',
            'message' => "O campo 'nome' está vazio.",
            'data' => [],
        ]);
        exit;
    }

    $conn = abreConexaoBD();
    $sql = "INSERT INTO marcas (nome, marca_status) VALUES (:nome, :status)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':status', $status);

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Marca inserida com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao inserir a marca.']);
    }
}

function listarMarcas($page = 1, $limit = 10, $status = 'ativo')
{
    // Verifica se a página e o limite estão corretos
    $offset = ($page - 1) * $limit;

    // Conexão com o banco de dados
    $conn = abreConexaoBD();

    // Verifica se a variável de status está definida corretamente
    if (empty($status)) {
        $status = 'ativo'; // Define um status padrão se estiver vazio
    }

    // SQL de listagem com filtro de status
    $sql = "SELECT * FROM marcas WHERE marca_status = :status LIMIT :limit OFFSET :offset";
    $stmt = $conn->prepare($sql);

    // Bind dos parâmetros
    $stmt->bindParam(':status', $status);
    $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);

    // Executa a consulta
    $stmt->execute();

    // Fetching the result
    $marcas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Verifica se retornou algum dado
    if ($marcas) {
        // Retorna as marcas no formato JSON
        respondeJson('success', 'Marcas listadas com sucesso.', $marcas);
    } else {
        // Caso não tenha retornado marcas
        respondeJson('error', 'Nenhuma marca encontrada com o status "' . $status . '".');
    }
}



function atualizarMarca($marca_id, $nome, $status = null) // O status agora é opcional
{
    if (empty($marca_id) || empty($nome)) {
        echo json_encode([
            'status' => 'error',
            'message' => "Os campos 'marca_id' e/ou 'nome' estão ausentes ou vazios.",
            'data' => [],
        ]);
        exit;
    }

    $conn = abreConexaoBD();
    $sql = "UPDATE marcas SET nome = :nome" . ($status ? ", marca_status = :status" : "") . " WHERE marca_id = :marca_id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':marca_id', $marca_id);
    if ($status) {
        $stmt->bindParam(':status', $status);
    }

    if ($stmt->execute()) {
        echo json_encode(['status' => 'success', 'message' => 'Marca atualizada com sucesso!']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao atualizar a marca.']);
    }
}


function excluirMarca($marca_id)
{
    if (empty($marca_id)) {
        respondeJson('error', "O campo 'marca_id' está vazio.");
    }

    $conn = abreConexaoBD();
    $sql = "DELETE FROM marcas WHERE marca_id = :marca_id";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':marca_id', $marca_id);

    if ($stmt->execute()) {
        respondeJson('success', 'Marca excluída com sucesso!');
    } else {
        respondeJson('error', 'Erro ao excluir a marca.');
    }
}

function carregarMarca($marca_status = 'ativo')
{
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM marcas WHERE marca_status = :status";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':status', $marca_status);
    $stmt->execute();

    $marcas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($marcas) {
        respondeJson('success', 'Marcas carregadas com sucesso.', $marcas);
    } else {
        respondeJson('error', 'Nenhuma marca encontrada.');
    }
}

function atualizarStatus($id, $status)
{
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
    header('Content-Type: application/json; charset=utf-8');

    // Verifica se os parâmetros são válidos
    if (!isset($id, $status) || empty($id)) {
        echo json_encode(['status' => 'error', 'message' => 'Parâmetros inválidos']);
        exit;
    }

    $conn = abreConexaoBD();

    if (!$conn) {
        echo json_encode(['status' => 'error', 'message' => 'Erro na conexão com o banco de dados']);
        exit;
    }

    try {
        // Prepara a query
        $sql = "UPDATE patrimonio SET status = :status WHERE id = :id";
        $stmt = $conn->prepare($sql);

        if (!$stmt) {
            echo json_encode(['status' => 'error', 'message' => 'Erro ao preparar a query']);
            exit;
        }

        $stmt->bindParam(':id', $id, PDO::PARAM_INT);
        $stmt->bindParam(':status', $status, PDO::PARAM_STR);

        // Executa e verifica se foi bem-sucedido
        if (!$stmt->execute()) {
            echo json_encode([
                'status' => 'error',
                'message' => 'Erro ao executar a query',
                'debug' => $stmt->errorInfo()
            ]);
            exit;
        }

        echo json_encode(['status' => 'success', 'message' => 'Status atualizado com sucesso']);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erro: ' . $e->getMessage()]);
    }
}


if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit; // Para as requisições OPTIONS
}

//$data = json_decode(file_get_contents("php://input"), true);
//$acao = $data['acao'] ?? null;
// Capturar dados da requisição
// Lógica principal para processar a requisição
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit; // Para as requisições OPTIONS
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);
    $acao = $data['acao'] ?? null;

    if (!$acao || !in_array($acao, ['logar', 'criaUsuarios', 'inserir', 'listar', 'altera', 'descartar', 'excluir', 'inserirMarca', 'listarMarcas', 'atualizarMarca', 'excluirMarca', 'carregarMarca', 'buscaResumoPatrimonio', 'atualizarStatus', 'inserirModelo', 'listarModelos', 'buscarModelos'])) {
        respondeJson('error', 'Ação inválida.');
    }

    try {
        switch ($acao) {
            case 'logar':
                logar($data['usuario'], $data['senha']);
                break;
            case 'criaUsuarios':
                criaUsuarios($data['usuario'], $data['senha']);
                break;
            case 'inserir':
                inserirDados(
                    $data['marca_status'],
                    $data['modelo'],
                    $data['cor'],
                    $data['codigo'],
                    $data['data'],
                    $data['foto'],
                    $data['status'],
                    $data['setor'],
                    $data['descricao']
                );
                break;
            case 'inserirModelo':
                inserirModelo(
                    $data['modelo'],
                    $data['cor'],
                    $data['imagemModelo'],
                    $data['descricao']
                );
                break;
            case 'listar':
                listaTodosProdutos();
                break;
            case 'altera':
                alteraPatrimonio($data);
                break;
            case 'descartar':
                if (isset($data['id'])) {
                    descartarProduto($data['id']);
                } else {
                    respondeJson('error', 'ID não fornecido.');
                }
                break;
            case 'excluir':
                apagaDadosPatrimonio($data['id']);
                break;
            case 'inserirMarca':
                $status = isset($data['status']) ? $data['status'] : 'ativo'; // Valor padrão 'ativo'
                inserirMarca($data['nome'], $status);
                break;
            case 'atualizarStatus':
                if (isset($data['id'], $data['status'])) {
                    atualizarStatus($data['id'], $data['status']);
                } else {
                    respondeJson('error', 'ID ou status não fornecido.');
                }
                break;

            case 'listarMarcas':
                $status = isset($data['status']) ? $data['status'] : 'ativo'; // Valor padrão 'ativo'
                $page = isset($data['page']) ? $data['page'] : 1;  // Valor padrão para 'page' (caso não esteja presente)
                $limit = isset($data['limit']) ? $data['limit'] : 10; // Valor padrão para 'limit' (caso não esteja presente)

                listarMarcas($page, $limit, $status);
                break;


            case 'atualizarMarca':
                if (empty($data['marca_id']) || empty($data['nome'])) {
                    respondeJson('error', "Os campos 'marca_id' e 'nome' são obrigatórios.");
                }
                $status = isset($data['status']) ? $data['status'] : null; // Status opcional
                atualizarMarca($data['marca_id'], $data['nome'], $status);
                break;

            case 'excluirMarca':
                excluirMarca($data['marca_id']);
                break;

            case 'buscaResumoPatrimonio':
                buscaResumoPatrimonio();
                break;

            case 'listarModelos': // Nova ação
                listarModelos();
                break;
            case 'buscarModelos': // Nova ação
                buscarModelo($data['modelo']);
                break;
            case 'carregarMarca':
                if (isset($data['marca_status'])) {
                    carregarMarca($data['marca_status']);
                } else {
                    respondeJson('error', 'Status não fornecido.');
                }
                break;

            default:
                respondeJson('error', 'Ação inválida ou não especificada.');
        }
    } catch (Exception $e) {
        respondeJson('error', 'Erro interno no servidor: ' . $e->getMessage());
    }
}
