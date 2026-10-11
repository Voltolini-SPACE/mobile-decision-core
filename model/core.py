"""Independent experimental typed decision model; not a Laya port.

Standard PyTorch blocks. All parameters are initialized and trained locally.
No foreign checkpoint, tokenizer, API, or teacher model is used.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from collections import Counter
import json, math, re, unicodedata
from pathlib import Path
from typing import Any
import torch
from torch import nn
import torch.nn.functional as F

class CapacityError(ValueError): pass

class Tokenizer:
    """Training-only word/punctuation vocabulary. Unknown words are counted, not hidden.
    This initial tokenizer is deliberately NOT advertised as a production multilingual one.
    """
    def __init__(self, vocab: dict[str,int]):
        self.vocab = dict(vocab)
        if self.vocab.get('<pad>') != 0 or self.vocab.get('<unk>') != 1:
            raise ValueError('invalid reserved tokens')
    @staticmethod
    def split(text: str) -> list[str]:
        return re.findall(r"\d|[^\W\d_]+|_|[^\w\s]", unicodedata.normalize('NFC', text).casefold(), re.UNICODE)
    @classmethod
    def fit(cls, texts: list[str]):
        counts=Counter(t for s in texts for t in cls.split(s))
        return cls({'<pad>':0,'<unk>':1, **{w:i+2 for i,w in enumerate(sorted(counts))}})
    def encode(self, text: str, cap: int) -> list[int]:
        tokens=self.split(text)
        if not tokens: raise ValueError('empty text')
        if len(tokens)>cap: raise CapacityError(f'{len(tokens)} tokens exceed capacity {cap}; no silent truncation')
        return [self.vocab.get(t,1) for t in tokens]
    def save(self,path): Path(path).write_text(json.dumps(self.vocab,ensure_ascii=False,indent=2))
    @classmethod
    def load(cls,path): return cls(json.loads(Path(path).read_text()))

def question_text(c:dict) -> str:
    return 'pergunta: '+c['question']+' estado: '+c['state']+' contexto: '+c.get('context','nenhum')

def validate_case(c:dict) -> None:
    if c.get('type') not in {'choice','boolean','ordinal'}: raise ValueError('unsupported type')
    if not isinstance(c.get('question'),str) or not c['question'].strip(): raise ValueError('missing question')
    if not isinstance(c.get('state'),str) or not c['state'].strip(): raise ValueError('missing state')
    options=c.get('options')
    if not isinstance(options,list) or not 2<=len(options)<=32: raise ValueError('need 2..32 options')
    ids=[]
    for o in options:
        if not isinstance(o.get('id'),str) or not o['id']: raise ValueError('invalid option id')
        if not isinstance(o.get('description'),str) or not o['description'].strip(): raise ValueError('invalid description')
        ids.append(o['id'])
    if len(ids)!=len(set(ids)): raise ValueError('duplicate option IDs')
    if c['type']=='boolean' and (any(type(o.get('value')) is not bool for o in options) or {o.get('value') for o in options}!={True,False}): raise ValueError('boolean values required')
    if c['type']=='ordinal':
        v=[o.get('value') for o in options]
        if any(type(x) not in (int,float) or not math.isfinite(x) for x in v) or len(set(v))!=len(v):
            raise ValueError('unique finite ordinal values required')

@dataclass
class Config:
    vocab_size:int
    dim:int=64
    layers:int=2
    query_cap:int=96
    option_cap:int=48

class ConvBlock(nn.Module):
    def __init__(self,d):
        super().__init__()
        self.depth=nn.Conv1d(d,d,3,padding=1,groups=d)
        self.mix=nn.Conv1d(d,2*d,1)
        self.norm=nn.LayerNorm(d)
    def forward(self,x,mask):
        y=F.glu(self.mix(F.gelu(self.depth(x.transpose(1,2)))),dim=1).transpose(1,2)
        return self.norm(x+y)*mask.unsqueeze(-1)

class TextEncoder(nn.Module):
    def __init__(self,cfg):
        super().__init__()
        d=cfg.dim
        self.embedding=nn.Embedding(cfg.vocab_size,d,padding_idx=0)
        self.dropout=nn.Dropout(.15)
        self.blocks=nn.ModuleList([ConvBlock(d) for _ in range(cfg.layers)])
        self.attn=nn.Linear(d,1)
        self.pool=nn.Linear(2*d,d)
    def forward(self,ids):
        mask=(ids!=0).to(self.embedding.weight.dtype)
        if self.training:
            ids=torch.where((ids!=0)&(torch.rand_like(ids,dtype=torch.float32)<.08),torch.ones_like(ids),ids)
        x=self.dropout(self.embedding(ids))*mask.unsqueeze(-1)
        for b in self.blocks: x=b(x,mask)
        a=self.attn(x).squeeze(-1).masked_fill(mask==0,-1e4).softmax(-1)
        attended=(x*a.unsqueeze(-1)).sum(1)
        mean=x.sum(1)/mask.sum(1,keepdim=True).clamp_min(1)
        return torch.tanh(self.pool(torch.cat([attended,mean],dim=-1)))

class DecisionModel(nn.Module):
    def __init__(self,cfg:Config):
        super().__init__(); self.cfg=cfg; self.encoder=TextEncoder(cfg)
        self.scorer=nn.Sequential(nn.Linear(4*cfg.dim,2*cfg.dim),nn.GELU(),nn.Linear(2*cfg.dim,1))
    def score(self,q,o):
        return self.scorer(torch.cat([q,o,q*o,torch.abs(q-o)],dim=-1)).squeeze(-1)
    def forward(self,query_ids,option_ids,option_mask):
        b,k,l=option_ids.shape
        q=self.encoder(query_ids)
        o=self.encoder(option_ids.reshape(b*k,l)).reshape(b,k,-1)
        scores=self.score(q.unsqueeze(1).expand(-1,k,-1),o)
        return scores.masked_fill(~option_mask,-1e4)
    def serial(self,query_ids,option_ids,option_mask):
        # Same model, same query representation; reference unbatched candidate encoder.
        q=self.encoder(query_ids)
        scores=[self.score(q,self.encoder(option_ids[:,i,:])) for i in range(option_ids.shape[1])]
        return torch.stack(scores,dim=1).masked_fill(~option_mask,-1e4)
    def cached(self,query_ids,option_vectors,option_mask):
        # Safe in this dual-encoder architecture; cache contains static option descriptions ONLY.
        q=self.encoder(query_ids)
        return self.score(q.unsqueeze(1).expand_as(option_vectors),option_vectors).masked_fill(~option_mask,-1e4)

def prepare(cases:list[dict],tok:Tokenizer,cfg:Config):
    for c in cases: validate_case(c)
    qs=[tok.encode(question_text(c),cfg.query_cap) for c in cases]
    os=[[tok.encode(o['description'],cfg.option_cap) for o in c['options']] for c in cases]
    b=len(cases); k=max(map(len,os)); ql=max(map(len,qs)); ol=max(len(o) for opts in os for o in opts)
    q=torch.zeros(b,ql,dtype=torch.long); o=torch.zeros(b,k,ol,dtype=torch.long); m=torch.zeros(b,k,dtype=torch.bool)
    for i,(qi,oi) in enumerate(zip(qs,os)):
        q[i,:len(qi)]=torch.tensor(qi)
        for j,ids in enumerate(oi): o[i,j,:len(ids)]=torch.tensor(ids);m[i,j]=True
    return q,o,m

class Engine:
    """Read-only decision proposal API. NEVER executes selected tools."""
    def __init__(self,model:DecisionModel,tok:Tokenizer,temperature:float=1.0):
        if type(temperature) not in (int,float) or not math.isfinite(temperature) or temperature<=0: raise ValueError('invalid temperature')
        self.model=model.eval();self.tok=tok;self.temperature=temperature
    @torch.inference_mode()
    def predict(self,c:dict,threshold:float|None=None)->dict[str,Any]:
        if threshold is not None and (type(threshold) not in (int,float) or not math.isfinite(threshold) or not 0<=threshold<=1): raise ValueError('invalid threshold')
        inputs=prepare([c],self.tok,self.model.cfg)
        p=torch.softmax(self.model(*inputs)[0]/self.temperature,dim=-1).tolist()
        if not all(math.isfinite(v) and 0<=v<=1 for v in p): raise ValueError('invalid neural result')
        i=max(range(len(p)),key=p.__getitem__)
        out={'type':c['type'],'candidate_id':c['options'][i]['id'],'selected_id':None if threshold is not None and p[i]<threshold else c['options'][i]['id'],'probabilities':{x['id']:v for x,v in zip(c['options'],p)},
             'top_probability':p[i],'abstained':threshold is not None and p[i]<threshold,
             'calibration_scope':'synthetic-development-only; not a production confidence guarantee',
             'decision_local':True,'execution':'not implemented; proposal only'}
        if c['type']=='boolean': out['probability_true']=sum(v for x,v in zip(c['options'],p) if x['value'] is True)
        if c['type']=='ordinal':
            out['selected_value']=c['options'][i]['value']
            out['expected_value']=sum(x['value']*v for x,v in zip(c['options'],p))
        return out


def masked_loss(logits,labels,valid_mask,smoothing:float=.015):
    """Label smoothing over VALID options only. Never encourage a padded action."""
    logp=torch.log_softmax(logits,dim=-1)
    nll=-logp.gather(-1,labels.unsqueeze(-1)).squeeze(-1)
    smooth=-(logp*valid_mask).sum(-1)/valid_mask.sum(-1).clamp_min(1)
    return ((1-smoothing)*nll+smoothing*smooth).mean()
