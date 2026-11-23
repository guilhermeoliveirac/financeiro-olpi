from __future__ import annotations

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.sessions.models import Session
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from .. import services as sv
from ..audit import registrar_auditoria
from ..forms import (
    IntegracaoAlertasForm, IntegracaoIAForm, IntegracaoTelegramForm, TokenAPIForm,
    UsuarioCriarForm, UsuarioEditarForm, UsuarioSenhaForm,
)
from ..models import Integracao, RegistroAuditoria, TentativaLogin, Titular, TokenAPI
from ..notificacoes import enviar_alertas, enviar_telegram
from ..security import gerar_token_api
from ._comum import _render_form

User = get_user_model()


@login_required
def admin_painel(request: HttpRequest) -> HttpResponse:
    agora = timezone.now()
    integracoes_map = {i.provedor: i for i in Integracao.objects.all()}
    return render(
        request,
        "financeiro/admin_painel.html",
        {
            "total_usuarios": User.objects.count(),
            "usuarios_ativos": User.objects.filter(is_active=True).count(),
            "sessoes_ativas": Session.objects.filter(expire_date__gt=agora).count(),
            "bloqueios_login": TentativaLogin.objects.filter(bloqueado_ate__gt=agora).count(),
            "tokens_ativos": TokenAPI.objects.filter(ativo=True).count(),
            "telegram": integracoes_map.get(Integracao.TELEGRAM),
            "ia": integracoes_map.get(Integracao.IA),
            "alertas_cfg": integracoes_map.get(Integracao.ALERTAS),
            "ultimos_logs": RegistroAuditoria.objects.select_related("usuario")[:12],
        },
    )


@login_required
def admin_usuarios(request: HttpRequest) -> HttpResponse:
    from ..models import Lancamento

    contagens = dict(
        Lancamento.objects.filter(criado_por__isnull=False)
        .order_by()
        .values_list("criado_por_id")
        .annotate(c=Count("id"))
    )
    lista = list(User.objects.select_related("titular").order_by("username"))
    for u in lista:
        u.qtd_lancamentos = contagens.get(u.pk, 0)
    return render(request, "financeiro/admin_usuarios.html", {"usuarios": lista})


@login_required
def admin_usuario_criar(request: HttpRequest) -> HttpResponse:
    form = UsuarioCriarForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        cd = form.cleaned_data
        with transaction.atomic():
            u = User.objects.create_user(
                username=cd["username"],
                email=cd["email"],
                password=cd["password1"],
                first_name=cd["first_name"],
                last_name=cd["last_name"],
                is_staff=cd["is_staff"],
                is_active=cd["is_active"],
            )
            tit = cd.get("titular")
            if tit:
                tit.usuario = u
                if cd.get("telegram_chat_id"):
                    tit.telegram_chat_id = cd["telegram_chat_id"].strip()
                tit.save()
            registrar_auditoria(
                request.user,
                RegistroAuditoria.ADMIN,
                u,
                f"Criou usuário: {u.username}",
                {"is_staff": u.is_staff, "titular": str(tit) if tit else ""},
                request=request,
            )
        messages.success(request, f"Usuário “{u.username}” criado.")
        return redirect("admin_usuarios")
    return _render_form(request, form, "Novo usuário", reverse("admin_usuarios"))


@login_required
def admin_usuario_editar(request: HttpRequest, pk: int) -> HttpResponse:
    u = get_object_or_404(User.objects.select_related("titular"), pk=pk)
    form = UsuarioEditarForm(request.POST or None, instance=u)
    if request.method == "POST" and form.is_valid():
        cd = form.cleaned_data
        if u.pk == request.user.pk and not cd["is_active"]:
            form.add_error("is_active", "Você não pode desativar o seu próprio usuário.")
        elif u.is_superuser and not cd["is_active"] and not User.objects.filter(is_active=True, is_superuser=True).exclude(pk=u.pk).exists():
            form.add_error("is_active", "Não é possível desativar o único superusuário ativo.")
        else:
            with transaction.atomic():
                u = form.save()
                tit = cd.get("titular")
                Titular.objects.filter(usuario=u).exclude(pk=tit.pk if tit else 0).update(usuario=None)
                if tit:
                    tit.usuario = u
                    tit.telegram_chat_id = (cd.get("telegram_chat_id") or "").strip()
                    tit.save()
                registrar_auditoria(
                    request.user,
                    RegistroAuditoria.ADMIN,
                    u,
                    f"Editou usuário: {u.username}",
                    {"is_active": u.is_active, "is_staff": u.is_staff, "titular": str(tit) if tit else ""},
                    request=request,
                )
            messages.success(request, f"Usuário “{u.username}” atualizado.")
            return redirect("admin_usuarios")
    return _render_form(
        request,
        form,
        f"Editar usuário: {u.username}",
        reverse("admin_usuarios"),
        aviso="Para redefinir a senha deste usuário, use a ação de troca de senha na lista de usuários.",
    )


@login_required
def admin_usuario_senha(request: HttpRequest, pk: int) -> HttpResponse:
    u = get_object_or_404(User, pk=pk)
    form = UsuarioSenhaForm(request.POST or None, usuario=u)
    if request.method == "POST" and form.is_valid():
        u.set_password(form.cleaned_data["nova_senha1"])
        u.save(update_fields=["password"])
        registrar_auditoria(
            request.user,
            RegistroAuditoria.ADMIN,
            u,
            f"Redefiniu senha do usuário: {u.username}",
            request=request,
        )
        messages.success(request, f"Senha de “{u.username}” atualizada.")
        return redirect("admin_usuarios")
    return _render_form(request, form, f"Redefinir senha · {u.username}", reverse("admin_usuarios"))


@login_required
def admin_sessoes(request: HttpRequest) -> HttpResponse:
    agora = timezone.now()
    sessoes_raw = list(Session.objects.filter(expire_date__gt=agora).order_by("-expire_date"))
    decodificadas = []
    user_ids = set()
    for s in sessoes_raw:
        try:
            data = s.get_decoded()
        except Exception:
            data = {}
        uid = data.get("_auth_user_id")
        if uid and str(uid).isdigit():
            user_ids.add(int(uid))
        decodificadas.append((s, int(uid) if uid and str(uid).isdigit() else None))

    users_map = User.objects.in_bulk(user_ids)
    sessoes = [
        {
            "session": s,
            "usuario": users_map.get(uid),
            "atual": s.session_key == request.session.session_key,
        }
        for s, uid in decodificadas
    ]
    tentativas = TentativaLogin.objects.order_by("-atualizado_em")[:50]
    return render(
        request,
        "financeiro/admin_sessoes.html",
        {"sessoes": sessoes, "tentativas": tentativas, "agora": agora},
    )


@login_required
@require_POST
def admin_sessao_encerrar(request: HttpRequest, key: str) -> HttpResponse:
    if key == request.session.session_key:
        messages.warning(request, "Use o botão Sair no menu para encerrar sua sessão atual.")
        return redirect("admin_sessoes")
    apagadas, _ = Session.objects.filter(session_key=key).delete()
    if apagadas:
        registrar_auditoria(
            request.user,
            RegistroAuditoria.ADMIN,
            "session",
            f"Encerrou sessão remota ({key[:8]}…)",
            request=request,
        )
        messages.success(request, "Sessão encerrada.")
    return redirect("admin_sessoes")


@login_required
@require_POST
def admin_desbloquear_login(request: HttpRequest, pk: int | None = None) -> HttpResponse:
    if pk:
        TentativaLogin.objects.filter(pk=pk).delete()
        msg = "Tentativa/bloqueio removido."
    else:
        TentativaLogin.objects.all().delete()
        msg = "Todos os bloqueios de login foram limpos."
    registrar_auditoria(request.user, RegistroAuditoria.ADMIN, "auth", msg, request=request)
    messages.success(request, msg)
    return redirect("admin_sessoes")


@login_required
def admin_integracoes(request: HttpRequest) -> HttpResponse:
    tg, _ = Integracao.objects.get_or_create(provedor=Integracao.TELEGRAM)
    ia, _ = Integracao.objects.get_or_create(provedor=Integracao.IA)
    al, _ = Integracao.objects.get_or_create(provedor=Integracao.ALERTAS)

    form_tg = IntegracaoTelegramForm(
        initial={"ativo": tg.ativo, "chat_id": (tg.config or {}).get("chat_id", "")}
    )
    form_ia = IntegracaoIAForm(
        initial={
            "ativo": ia.ativo,
            "provedor_ia": (ia.config or {}).get("provedor_ia", "gemini"),
            "modelo": (ia.config or {}).get("modelo", ""),
            "endpoint": (ia.config or {}).get("endpoint", ""),
            "instrucoes": (ia.config or {}).get("instrucoes", ""),
        }
    )
    form_al = IntegracaoAlertasForm(
        initial={
            "ativo": al.ativo,
            "dias_vencimento": (al.config or {}).get("dias_vencimento", 3),
            "orcamento_pct": (al.config or {}).get("orcamento_pct", 80),
            "incluir_veiculos": (al.config or {}).get("incluir_veiculos", True),
        }
    )

    if request.method == "POST":
        alvo = request.POST.get("provedor")
        if alvo == Integracao.TELEGRAM:
            form_tg = IntegracaoTelegramForm(request.POST)
            if form_tg.is_valid():
                cd = form_tg.cleaned_data
                tg.ativo = cd["ativo"]
                tg.config = {"chat_id": cd["chat_id"].strip()}
                if cd["token"].strip():
                    tg.segredo = cd["token"].strip()
                tg.atualizado_por = request.user
                tg.save()
                registrar_auditoria(
                    request.user, RegistroAuditoria.ADMIN, tg, "Atualizou integração Telegram", request=request
                )
                messages.success(request, "Configurações do Telegram salvas.")
                return redirect("admin_integracoes")
        elif alvo == Integracao.IA:
            form_ia = IntegracaoIAForm(request.POST)
            if form_ia.is_valid():
                cd = form_ia.cleaned_data
                ia.ativo = cd["ativo"]
                ia.config = {
                    "provedor_ia": cd["provedor_ia"],
                    "modelo": cd["modelo"].strip(),
                    "endpoint": cd["endpoint"].strip(),
                    "instrucoes": cd["instrucoes"].strip(),
                }
                if cd["api_key"].strip():
                    ia.segredo = cd["api_key"].strip()
                ia.atualizado_por = request.user
                ia.save()
                registrar_auditoria(
                    request.user, RegistroAuditoria.ADMIN, ia, f"Atualizou integração IA ({cd['provedor_ia']})", request=request
                )
                messages.success(request, "Configurações de IA salvas.")
                return redirect("admin_integracoes")
        elif alvo == Integracao.ALERTAS:
            form_al = IntegracaoAlertasForm(request.POST)
            if form_al.is_valid():
                cd = form_al.cleaned_data
                al.ativo = cd["ativo"]
                al.config = {
                    "dias_vencimento": cd["dias_vencimento"],
                    "orcamento_pct": cd["orcamento_pct"],
                    "incluir_veiculos": cd["incluir_veiculos"],
                }
                al.atualizado_por = request.user
                al.save()
                registrar_auditoria(
                    request.user, RegistroAuditoria.ADMIN, al, "Atualizou regras de alertas automáticos", request=request
                )
                messages.success(request, "Configurações de alertas salvas.")
                return redirect("admin_integracoes")

    return render(
        request,
        "financeiro/admin_integracoes.html",
        {
            "form_tg": form_tg,
            "form_ia": form_ia,
            "form_al": form_al,
            "tg_mascara": tg.segredo_mascarado(),
            "ia_mascara": ia.segredo_mascarado(),
        },
    )


@login_required
@require_POST
def admin_integracao_testar_telegram(request: HttpRequest) -> HttpResponse:
    ok, detalhe = enviar_telegram("Teste de conexão · Finanças de Casa (OLPI) funcionando!")
    if ok:
        messages.success(request, detalhe)
    else:
        messages.error(request, detalhe)
    return redirect("admin_integracoes")


@login_required
def admin_tokens(request: HttpRequest) -> HttpResponse:
    novo_token = request.session.pop("novo_token_api", None)
    form = TokenAPIForm(request.POST or None, initial={"usuario": request.user.pk})
    if request.method == "POST" and form.is_valid():
        cd = form.cleaned_data
        inst, plano = gerar_token_api(cd["nome"], cd["usuario"])
        request.session["novo_token_api"] = {"nome": inst.nome, "token": plano}
        registrar_auditoria(
            request.user,
            RegistroAuditoria.ADMIN,
            inst,
            f"Gerou token de API: {inst.nome} ({inst.prefixo}…)",
            request=request,
        )
        messages.success(request, "Token de API gerado. Copie-o agora — ele não será exibido novamente.")
        return redirect("admin_tokens")
    tokens = TokenAPI.objects.select_related("usuario").order_by("-criado_em")
    return render(
        request,
        "financeiro/admin_tokens.html",
        {"form": form, "tokens": tokens, "novo_token": novo_token},
    )


@login_required
@require_POST
def admin_token_revogar(request: HttpRequest, pk: int) -> HttpResponse:
    tok = get_object_or_404(TokenAPI, pk=pk)
    tok.ativo = False
    tok.save(update_fields=["ativo"])
    registrar_auditoria(
        request.user,
        RegistroAuditoria.ADMIN,
        tok,
        f"Revogou token de API: {tok.nome}",
        request=request,
    )
    messages.success(request, f"Token “{tok.nome}” revogado.")
    return redirect("admin_tokens")


@login_required
def admin_auditoria(request: HttpRequest) -> HttpResponse:
    qs = RegistroAuditoria.objects.select_related("usuario")
    usuario_id = request.GET.get("usuario", "")
    if usuario_id.isdigit():
        qs = qs.filter(usuario_id=usuario_id)
    acao = request.GET.get("acao", "")
    if acao:
        qs = qs.filter(acao=acao)
    modelo = request.GET.get("modelo", "")
    if modelo:
        qs = qs.filter(modelo=modelo)
    busca = request.GET.get("q", "").strip()
    if busca:
        qs = qs.filter(Q(resumo__icontains=busca) | Q(objeto_id__icontains=busca))

    pagina = Paginator(qs, 40).get_page(request.GET.get("page"))
    g = request.GET.copy()
    g.pop("page", None)
    return render(
        request,
        "financeiro/admin_auditoria.html",
        {
            "pagina": pagina,
            "f": request.GET,
            "querystring": g.urlencode(),
            "usuarios": User.objects.order_by("username"),
            "acoes": RegistroAuditoria.ACOES,
            "modelos": RegistroAuditoria.objects.order_by().values_list("modelo", flat=True).distinct(),
        },
    )


@login_required
@require_POST
def admin_sistema_acao(request: HttpRequest) -> HttpResponse:
    acao = request.POST.get("acao")
    if acao == "gerar_recorrencias":
        criados = sv.gerar_recorrencias(forcar=True)
        registrar_auditoria(
            request.user, RegistroAuditoria.ADMIN, "recorrencia", f"Gerou {criados} lançamento(s) recorrente(s)", request=request
        )
        messages.success(request, f"{criados} lançamento(s) recorrente(s) gerado(s).")
    elif acao == "recalcular_faturas":
        alt = sv.recalcular_todas_faturas()
        registrar_auditoria(
            request.user, RegistroAuditoria.ADMIN, "fatura", f"Recalculou faturas ({alt} alterada(s))", request=request
        )
        messages.success(request, f"Faturas verificadas ({alt} atualizada(s)).")
    elif acao == "simular_alertas":
        res = enviar_alertas(dry_run=True)
        messages.info(request, f"Simulação: {res['total']} alerta(s). Prévia: {res['mensagem'][:300]}")
    elif acao == "enviar_alertas":
        res = enviar_alertas(dry_run=False)
        if res["enviado"]:
            messages.success(request, f"Alertas enviados ({res['total']} item(ns)).")
        else:
            messages.warning(request, f"Não enviado: {res['motivo']} ({res['total']} alerta(s)).")
    return redirect("admin_painel")
