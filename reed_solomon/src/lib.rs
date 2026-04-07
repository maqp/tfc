/*
 * TFC - Onion-routed, endpoint secure messaging system
 * Copyright (C) 2013-2026  Markus Ottela
 *
 * This file is part of TFC.
 * TFC is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version. TFC is
 * distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details. You should have received a
 * copy of the GNU General Public License along with TFC. If not, see
 * <https://www.gnu.org/licenses/>.
 */


#![forbid(unsafe_code)]
#![allow(clippy::useless_conversion)]

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

#[derive(Debug, Clone)]
struct RsCtx {
    nsym: usize,
    nsize: usize,
    fcr: i32,
    prim: u16,
    generator: u8,
    gf_log: [u8; 256],
    gf_exp: [u8; 512],
    gen: Vec<u8>,
}

#[derive(Debug, Clone)]
enum RsErr {
    Arg(&'static str),
    TooLong(&'static str),
    TooManyErasures,
    Locate,
    Correct,
}

impl RsCtx {
    fn new(nsym: usize, nsize: usize, fcr: i32, prim: u16, generator: u8) -> Result<Self, RsErr> {
        if nsize == 0 || nsize > 255 {
            return Err(RsErr::Arg("nsize must be in 1..=255 for GF(2^8)"));
        }
        if nsym == 0 || nsym >= nsize {
            return Err(RsErr::Arg("nsym must be in 1..nsize-1"));
        }
        if generator != 2 {
            return Err(RsErr::Arg(
                "only generator=2 is supported in this implementation",
            ));
        }

        let mut ctx = RsCtx {
            nsym,
            nsize,
            fcr,
            prim,
            generator,
            gf_log: [0u8; 256],
            gf_exp: [0u8; 512],
            gen: Vec::new(),
        };

        ctx.init_tables();
        ctx.gen = ctx.rs_generator_poly(nsym)?;

        Ok(ctx)
    }

    fn init_tables(&mut self) {
        self.gf_log = [0u8; 256];
        self.gf_exp = [0u8; 512];

        let mut x: u16 = 1;

        for i in 0..255 {
            self.gf_exp[i] = (x & 0xFF) as u8;
            self.gf_log[(x & 0xFF) as usize] = i as u8;

            x <<= 1;
            if (x & 0x100) != 0 {
                x ^= self.prim;
            }
            x &= 0x1FF;
        }

        for i in 255..512 {
            self.gf_exp[i] = self.gf_exp[i - 255];
        }
    }

    #[inline]
    fn gf_mul(&self, x: u8, y: u8) -> u8 {
        if x == 0 || y == 0 {
            return 0;
        }
        let lx = self.gf_log[x as usize] as usize;
        let ly = self.gf_log[y as usize] as usize;
        self.gf_exp[lx + ly]
    }

    #[inline]
    fn gf_div(&self, x: u8, y: u8) -> Result<u8, RsErr> {
        if y == 0 {
            return Err(RsErr::Arg("division by zero in GF"));
        }
        if x == 0 {
            return Ok(0);
        }
        let lx = self.gf_log[x as usize] as i32;
        let ly = self.gf_log[y as usize] as i32;
        let mut r = lx + 255 - ly;
        r %= 255;
        if r < 0 {
            r += 255;
        }
        Ok(self.gf_exp[r as usize])
    }

    #[inline]
    fn gf_inverse(&self, x: u8) -> Result<u8, RsErr> {
        if x == 0 {
            return Err(RsErr::Arg("inverse(0) undefined"));
        }
        Ok(self.gf_exp[255 - self.gf_log[x as usize] as usize])
    }

    #[inline]
    fn gf_pow(&self, x: u8, power: i32) -> u8 {
        if power == 0 {
            return 1;
        }
        if x == 0 {
            return 0;
        }
        let logx = self.gf_log[x as usize] as i32;
        let mut r = (logx * power) % 255;
        if r < 0 {
            r += 255;
        }
        self.gf_exp[r as usize]
    }

    fn gf_poly_add_aligned(p: &[u8], q: &[u8]) -> Vec<u8> {
        let r_len = p.len().max(q.len());
        let mut r = vec![0u8; r_len];

        r[r_len - p.len()..].copy_from_slice(p);

        let off = r_len - q.len();
        for i in 0..q.len() {
            r[off + i] ^= q[i];
        }

        r
    }

    fn gf_poly_scale(&self, p: &[u8], x: u8) -> Vec<u8> {
        p.iter().map(|&c| self.gf_mul(c, x)).collect()
    }

    fn gf_poly_mul(&self, p: &[u8], q: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; p.len() + q.len() - 1];

        let lp: Vec<u8> = p.iter().map(|&c| self.gf_log[c as usize]).collect();

        for (j, &qj) in q.iter().enumerate() {
            if qj == 0 {
                continue;
            }
            let lq = self.gf_log[qj as usize] as usize;

            for (i, &pi) in p.iter().enumerate() {
                if pi == 0 {
                    continue;
                }
                let li = lp[i] as usize;
                r[i + j] ^= self.gf_exp[li + lq];
            }
        }

        r
    }

    fn gf_poly_eval(&self, poly: &[u8], x: u8) -> u8 {
        let mut y = poly[0];
        for &c in &poly[1..] {
            y = self.gf_mul(y, x) ^ c;
        }
        y
    }

    fn gf_poly_div(&self, dividend: &[u8], divisor: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut msg_out = dividend.to_vec();

        for i in 0..(dividend.len() - (divisor.len() - 1)) {
            let coef = msg_out[i];
            if coef != 0 {
                for j in 1..divisor.len() {
                    let dj = divisor[j];
                    if dj != 0 {
                        msg_out[i + j] ^= self.gf_mul(dj, coef);
                    }
                }
            }
        }

        let sep = dividend.len() - (divisor.len() - 1);
        let q = msg_out[..sep].to_vec();
        let r = msg_out[sep..].to_vec();

        (q, r)
    }

    fn rs_generator_poly(&self, nsym: usize) -> Result<Vec<u8>, RsErr> {
        let mut g: Vec<u8> = vec![1];

        for i in 0..nsym {
            let a = self.gf_pow(self.generator, (i as i32) + self.fcr);
            let term = [1u8, a];
            g = self.gf_poly_mul(&g, &term);
        }

        Ok(g)
    }

    fn rs_encode_msg(&self, msg: &[u8]) -> Result<Vec<u8>, RsErr> {
        if msg.len() + self.nsym > 255 {
            return Err(RsErr::TooLong("message too long for GF(256)"));
        }

        let mut dividend = Vec::with_capacity(msg.len() + self.nsym);
        dividend.extend_from_slice(msg);
        dividend.extend(std::iter::repeat_n(0u8, self.nsym));

        let (_q, rem) = self.gf_poly_div(&dividend, &self.gen);

        let mut out = Vec::with_capacity(msg.len() + self.nsym);
        out.extend_from_slice(msg);
        out.extend_from_slice(&rem);

        Ok(out)
    }

    fn rs_calc_syndromes(&self, msg: &[u8]) -> Vec<u8> {
        let mut synd = vec![0u8; self.nsym + 1];
        synd[0] = 0;

        for i in 0..self.nsym {
            let x = self.gf_pow(self.generator, (i as i32) + self.fcr);
            synd[i + 1] = self.gf_poly_eval(msg, x);
        }

        synd
    }

    fn rs_forney_syndromes(&self, synd: &[u8], erase_pos_abs: &[usize], nmess: usize) -> Vec<u8> {
        let mut fsynd = synd[1..].to_vec();

        for &p in erase_pos_abs {
            let erase_pos_reversed = (nmess - 1) as i32 - (p as i32);
            let x = self.gf_pow(self.generator, erase_pos_reversed);

            for j in 0..(fsynd.len() - 1) {
                fsynd[j] = self.gf_mul(fsynd[j], x) ^ fsynd[j + 1];
            }
        }

        fsynd
    }

    fn rs_find_error_locator(&self, fsynd: &[u8], erase_count: usize) -> Result<Vec<u8>, RsErr> {
        let mut err_loc: Vec<u8> = vec![1];
        let mut old_loc: Vec<u8> = vec![1];

        let iters = self.nsym - erase_count;

        for i in 0..iters {
            let k = i;

            let mut delta = fsynd[k];
            for j in 1..err_loc.len() {
                let a = err_loc[err_loc.len() - 1 - j];
                let b = fsynd[k - j];
                delta ^= self.gf_mul(a, b);
            }

            old_loc.push(0);

            if delta != 0 {
                if old_loc.len() > err_loc.len() {
                    let prev_err = err_loc.clone();
                    let prev_old = old_loc.clone();

                    let new_loc = self.gf_poly_scale(&prev_old, delta);
                    let invd = self.gf_inverse(delta)?;
                    let new_old = self.gf_poly_scale(&prev_err, invd);

                    err_loc = new_loc;
                    old_loc = new_old;
                }

                let scaled = self.gf_poly_scale(&old_loc, delta);
                err_loc = Self::gf_poly_add_aligned(&err_loc, &scaled);
            }
        }

        while err_loc.len() > 1 && err_loc[0] == 0 {
            err_loc.remove(0);
        }

        let errs = err_loc.len().saturating_sub(1);
        if errs >= 1 && (errs.saturating_sub(erase_count)) * 2 + erase_count > self.nsym {
            return Err(RsErr::Correct);
        }

        Ok(err_loc)
    }

    fn rs_find_errors(&self, err_loc: &[u8], nmess: usize) -> Result<Vec<usize>, RsErr> {
        let errs = err_loc.len().saturating_sub(1);
        let mut err_pos = Vec::with_capacity(errs);

        for i in 0..nmess {
            let x = self.gf_pow(self.generator, i as i32);
            if self.gf_poly_eval(err_loc, x) == 0 {
                err_pos.push(nmess - 1 - i);
            }
        }

        if err_pos.len() != errs {
            return Err(RsErr::Locate);
        }

        Ok(err_pos)
    }

    fn rs_find_errata_locator(&self, coef_pos: &[i32]) -> Vec<u8> {
        let mut e_loc: Vec<u8> = vec![1];

        for &i in coef_pos {
            let a = self.gf_pow(self.generator, i);
            let term = [a, 1u8];
            e_loc = self.gf_poly_mul(&e_loc, &term);
        }

        e_loc
    }

    fn rs_find_error_evaluator(&self, synd: &[u8], err_loc: &[u8], nsym: usize) -> Vec<u8> {
        let mul = self.gf_poly_mul(synd, err_loc);
        let keep = (nsym + 1).min(mul.len());
        mul[mul.len() - keep..].to_vec()
    }

    fn rs_correct_errata(&self, msg: &mut [u8], synd: &[u8], err_pos: &[usize]) -> Result<(), RsErr> {
        let nmess = msg.len();

        let coef_pos: Vec<i32> = err_pos.iter().map(|&p| (nmess - 1 - p) as i32).collect();
        let err_loc = self.rs_find_errata_locator(&coef_pos);

        let mut synd_rev = synd.to_vec();
        synd_rev.reverse();

        let mut err_eval = self.rs_find_error_evaluator(&synd_rev, &err_loc, err_loc.len() - 1);
        err_eval.reverse();

        let mut x: Vec<u8> = Vec::with_capacity(coef_pos.len());
        for &cp in &coef_pos {
            let pos = 255 - cp;
            x.push(self.gf_pow(self.generator, -pos));
        }

        let mut e = vec![0u8; nmess];

        for (i, &xi) in x.iter().enumerate() {
            let xi_inv = self.gf_inverse(xi)?;

            let mut err_loc_prime = 1u8;
            for (j, &xj) in x.iter().enumerate() {
                if j == i {
                    continue;
                }
                let term = 1u8 ^ self.gf_mul(xi_inv, xj);
                err_loc_prime = self.gf_mul(err_loc_prime, term);
            }

            let mut err_eval_rev = err_eval.clone();
            err_eval_rev.reverse();

            let mut y = self.gf_poly_eval(&err_eval_rev, xi_inv);
            y = self.gf_mul(self.gf_pow(xi, 1 - self.fcr), y);

            let magnitude = self.gf_div(y, err_loc_prime)?;
            e[err_pos[i]] = magnitude;
        }

        for i in 0..nmess {
            msg[i] ^= e[i];
        }

        Ok(())
    }

    fn rs_correct_msg(
        &self,
        codeword: &[u8],
        erase_pos_abs: Option<&[usize]>,
        only_erasures: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), RsErr> {
        if codeword.len() > self.nsize {
            return Err(RsErr::TooLong("chunk longer than nsize"));
        }
        if codeword.len() < self.nsym {
            return Err(RsErr::Arg("codeword shorter than nsym"));
        }

        let mut msg_out = codeword.to_vec();

        let erase_pos = erase_pos_abs.unwrap_or(&[]);
        if erase_pos.len() > self.nsym {
            return Err(RsErr::TooManyErasures);
        }

        for &p in erase_pos {
            if p >= msg_out.len() {
                return Err(RsErr::Arg("erase_pos out of range"));
            }
            msg_out[p] = 0;
        }

        let mut synd = self.rs_calc_syndromes(&msg_out);
        if synd.iter().all(|&x| x == 0) {
            let (m, ecc) = msg_out.split_at(msg_out.len() - self.nsym);
            return Ok((m.to_vec(), ecc.to_vec()));
        }

        let mut err_pos: Vec<usize> = Vec::new();

        if !only_erasures {
            let fsynd = self.rs_forney_syndromes(&synd, erase_pos, msg_out.len());
            let err_loc = self.rs_find_error_locator(&fsynd, erase_pos.len())?;

            let mut err_loc_rev = err_loc.clone();
            err_loc_rev.reverse();

            err_pos = self.rs_find_errors(&err_loc_rev, msg_out.len())?;
        }

        let mut all_pos = Vec::with_capacity(erase_pos.len() + err_pos.len());
        all_pos.extend_from_slice(erase_pos);
        all_pos.extend_from_slice(&err_pos);

        self.rs_correct_errata(&mut msg_out, &synd, &all_pos)?;

        synd = self.rs_calc_syndromes(&msg_out);
        if !synd.iter().all(|&x| x == 0) {
            return Err(RsErr::Correct);
        }

        let (m, ecc) = msg_out.split_at(msg_out.len() - self.nsym);
        Ok((m.to_vec(), ecc.to_vec()))
    }

    fn encode_stream(&self, data: &[u8]) -> Result<Vec<u8>, RsErr> {
        let mut out = Vec::new();
        let chunk_msg_len = self.nsize - self.nsym;

        for chunk in data.chunks(chunk_msg_len) {
            out.extend_from_slice(&self.rs_encode_msg(chunk)?);
        }

        Ok(out)
    }

    fn decode_stream(
        &self,
        data: &[u8],
        erase_pos_abs: Option<&[usize]>,
        only_erasures: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), RsErr> {
        let mut dec = Vec::new();
        let mut dec_full = Vec::new();

        let mut erase = erase_pos_abs.unwrap_or(&[]).to_vec();
        erase.sort_unstable();

        for (chunk_index, chunk) in data.chunks(self.nsize).enumerate() {
            let start = chunk_index * self.nsize;
            let end = start + chunk.len();

            let epos: Vec<usize> = erase
                .iter()
                .copied()
                .filter(|p| *p >= start && *p < end)
                .map(|p| p - start)
                .collect();

            let (m, ecc) = self.rs_correct_msg(chunk, Some(&epos), only_erasures)?;
            dec.extend_from_slice(&m);
            dec_full.extend_from_slice(&m);
            dec_full.extend_from_slice(&ecc);
        }

        Ok((dec, dec_full))
    }

    fn check_stream(&self, data: &[u8]) -> Result<Vec<bool>, RsErr> {
        let mut out = Vec::new();
        for chunk in data.chunks(self.nsize) {
            let synd = self.rs_calc_syndromes(chunk);
            out.push(synd.iter().all(|&x| x == 0));
        }
        Ok(out)
    }
}

fn rs_err_to_py(err: RsErr) -> PyErr {
    match err {
        RsErr::Arg(m) => PyValueError::new_err(format!("ReedSolomonError: {m}")),
        RsErr::TooLong(m) => PyValueError::new_err(format!("ReedSolomonError: {m}")),
        RsErr::TooManyErasures => PyValueError::new_err("ReedSolomonError: too many erasures"),
        RsErr::Locate => PyValueError::new_err("ReedSolomonError: could not locate errors"),
        RsErr::Correct => PyValueError::new_err("ReedSolomonError: could not correct message"),
    }
}

#[pyclass]
struct RSCodec {
    ctx: RsCtx,
}

#[allow(clippy::useless_conversion)]
#[pymethods]
impl RSCodec {
    #[new]
    #[pyo3(signature = (nsym=10, nsize=255, fcr=0, prim=0x11d, generator=2))]
    fn new(nsym: usize, nsize: usize, fcr: i32, prim: u16, generator: u8) -> PyResult<Self> {
        let ctx = RsCtx::new(nsym, nsize, fcr, prim, generator).map_err(rs_err_to_py)?;
        Ok(RSCodec { ctx })
    }

    #[allow(clippy::useless_conversion)]
    fn encode(&self, data: &[u8]) -> PyResult<Vec<u8>> {
        self.ctx.encode_stream(data).map_err(rs_err_to_py)
    }

    #[allow(clippy::useless_conversion)]
    #[pyo3(signature = (data, erase_pos=None, only_erasures=false))]
    fn decode(
        &self,
        data: &[u8],
        erase_pos: Option<Vec<usize>>,
        only_erasures: bool,
    ) -> PyResult<(Vec<u8>, Vec<u8>)> {
        self.ctx
            .decode_stream(data, erase_pos.as_deref(), only_erasures)
            .map_err(rs_err_to_py)
    }

    #[allow(clippy::useless_conversion)]
    fn check(&self, data: &[u8]) -> PyResult<Vec<bool>> {
        self.ctx.check_stream(data).map_err(rs_err_to_py)
    }

    #[getter]
    fn nsym(&self) -> PyResult<usize> {
        Ok(self.ctx.nsym)
    }

    #[getter]
    fn nsize(&self) -> PyResult<usize> {
        Ok(self.ctx.nsize)
    }
}

#[pymodule]
fn reed_solomon(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RSCodec>()?;
    Ok(())
}
