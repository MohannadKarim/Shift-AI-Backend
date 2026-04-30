from fastapi import APIRouter, HTTPException, Depends
from app.dependencies import get_current_user, admin_only
from app.services.firebase import get_db
from app.models.models import WorkflowCreate

router = APIRouter()


@router.get("/")
def list_workflows(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = db.collection("workflows").stream()
    return [{"id": doc.id, **doc.to_dict()} for doc in docs]


@router.get("/{workflow_id}")
def get_workflow(workflow_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection("workflows").document(workflow_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Workflow not found")
    return {"id": doc.id, **doc.to_dict()}


@router.post("/")
def create_workflow(body: WorkflowCreate, user: dict = Depends(admin_only)):
    db = get_db()
    doc_ref = db.collection("workflows").document()
    data = body.model_dump()
    data["usageCount"] = 0
    data["contributors"] = []
    doc_ref.set(data)
    return {"id": doc_ref.id, **data}


@router.put("/{workflow_id}")
def update_workflow(workflow_id: str, body: WorkflowCreate, user: dict = Depends(admin_only)):
    db = get_db()
    doc = db.collection("workflows").document(workflow_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Workflow not found")
    db.collection("workflows").document(workflow_id).update(body.model_dump())
    return {"id": workflow_id, **body.model_dump()}


@router.delete("/{workflow_id}")
def delete_workflow(workflow_id: str, user: dict = Depends(admin_only)):
    db = get_db()
    doc = db.collection("workflows").document(workflow_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Workflow not found")
    db.collection("workflows").document(workflow_id).delete()
    return {"message": "Workflow deleted"}
