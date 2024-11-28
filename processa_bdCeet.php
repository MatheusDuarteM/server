<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json; charset=utf-8");

function abreConexaoBD() {
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

function validaUsuario($usuario, $senha) {
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM usuario WHERE usuario = :usuario AND senha = :senha";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':usuario', $usuario);
    $stmt->bindParam(':senha', $senha);
    $stmt->execute();
    
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function logar($usuario, $senha) {
    $usuarioValidado = validaUsuario($usuario, $senha);
    
    if ($usuarioValidado) {
        echo json_encode(['status' => 'success', 'message' => 'Login bem-sucedido!', 'usuario' => $usuarioValidado]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Usuário ou senha inválidos.']);
    }
}

function criaUsuarios($usuario, $senha) {
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

function inserirDados($marca, $modelo, $cor, $codigo, $data, $fotoBase64, $status, $setor, $descricao) {
    if (!$marca || !$modelo || !$cor || !$codigo || !$data || !$status || !$setor || !$descricao) {
        echo json_encode(['status' => 'error', 'message' => 'Dados incompletos para inserção']);
        return;
    }

    $conn = abreConexaoBD();
    $fotoNome = uniqid() . '.png';
    $fotoCaminho = 'imagens/' . $fotoNome;

    if (!file_exists('imagens')) {
        mkdir('imagens', 0777, true);
    }

    if ($fotoBase64 && base64_decode($fotoBase64, true)) {
        file_put_contents($fotoCaminho, base64_decode($fotoBase64));
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Imagem inválida']);
        return;
    }

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

function listaTodosProdutos() {
    $conn = abreConexaoBD();
    $sql = "SELECT * FROM patrimonio";
    $stmt = $conn->prepare($sql);
    $stmt->execute();
    $produtos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['status' => 'success', 'produtos' => $produtos ?: []]);
}

function alteraPatrimonio($data) {
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

    // Atualizar a imagem se a base64 estiver presente
    if (!empty($fotoBase64)) {
        $fotoNome = uniqid() . '.png';
        $fotoCaminho = 'imagens/' . $fotoNome;

        if (!file_exists('imagens')) {
            mkdir('imagens', 0777, true);
        }

        if ($fotoBase64 && base64_decode($fotoBase64, true)) {
            file_put_contents($fotoCaminho, base64_decode($fotoBase64));
            $stmt->bindParam(':imagem', $fotoCaminho);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Imagem inválida']);
            return;
        }
    }

    try {
        if ($stmt->execute()) {
            echo json_encode(['status' => 'success', 'message' => 'Patrimônio atualizado com sucesso!']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Erro ao executar a atualização.']);
        }
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erro ao atualizar patrimônio: ' . $e->getMessage()]);
    }
}

function apagaDadosPatrimonio($id) {
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
function descartarProduto($id) {
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

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit; // Para as requisições OPTIONS
}

$data = json_decode(file_get_contents("php://input"), true);
$acao = $data['acao'] ?? null;

switch ($acao) {
    case 'logar':
        logar($data['usuario'], $data['senha']);
        break;
    case 'criaUsuarios':
        criaUsuarios($data['usuario'], $data['senha']);
        break;
    case 'inserir':
        inserirDados($data['marca'], $data['modelo'], $data['cor'], $data['codigo'], $data['data'], $data['foto'], $data['status'], $data['setor'], $data['descricao']);
        break;
    case 'listar':
        listaTodosProdutos();
        break;
    case 'altera':
        alteraPatrimonio($data);
        break;
    case 'descartar':
        if (isset($data['id'])) {
            descartarProduto($data['id']); // Função que altera o status no banco
        } else {
            echo json_encode(['status' => 'error', 'message' => 'ID não fornecido ou inválido']);
        }     
        break;
    case 'excluir':
        apagaDadosPatrimonio($data['id']);
        break;
    default:
        echo json_encode(['status' => 'error', 'message' => 'Ação não reconhecida.']);
        break;
}
?>
