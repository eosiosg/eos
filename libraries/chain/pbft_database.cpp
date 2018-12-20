//
// Created by deadlock on 19/10/18.
//

#include <eosio/chain/pbft_database.hpp>
#include <fc/io/fstream.hpp>
#include <fstream>
#include <eosio/chain/global_property_object.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace eosio {
    namespace chain {

        pbft_database::pbft_database( controller &ctrl) :
        ctrl(ctrl),
        view_state_index(pbft_view_state_multi_index_type{})
        {
            checkpoint_index = pbft_checkpoint_state_multi_index_type{};
            pbft_db_dir = ctrl.state_dir();
            checkpoints_dir = ctrl.blocks_dir();

            if (!fc::is_directory(pbft_db_dir)) fc::create_directories(pbft_db_dir);

            auto pbft_db_dat = pbft_db_dir / config::pbftdb_filename;
            if (fc::exists(pbft_db_dat)) {
                string content;
                fc::read_file_contents(pbft_db_dat, content);

                fc::datastream<const char *> ds(content.data(), content.size());

                // keep these unused variables, cos these are the first 2 values in the stream.
                uint32_t current_view;
                fc::raw::unpack(ds, current_view);

                unsigned_int size;
                fc::raw::unpack(ds, size);
                for (uint32_t i = 0, n = size.value; i < n; ++i) {
                    pbft_state s;
                    fc::raw::unpack(ds, s);
                    set(std::make_shared<pbft_state>(move(s)));
                }
                ilog("index size: ${s}", ("s", index.size()));
            } else {
                index = pbft_state_multi_index_type{};
            }

            if (!fc::is_directory(checkpoints_dir)) fc::create_directories(checkpoints_dir);

            auto checkpoints_db = checkpoints_dir / config::checkpoints_filename;
            if (fc::exists(checkpoints_db)) {
                string content;
                fc::read_file_contents(checkpoints_db, content);

                fc::datastream<const char *> ds(content.data(), content.size());

                unsigned_int checkpoint_size;
                fc::raw::unpack(ds, checkpoint_size);
                for (uint32_t j = 0, m = checkpoint_size.value; j < m; ++j) {
                    pbft_checkpoint_state cs;
                    fc::raw::unpack(ds, cs);
                    set(std::make_shared<pbft_checkpoint_state>(move(cs)));
                }
                ilog("checkpoint index size: ${cs}", ("cs", checkpoint_index.size()));
            } else {
                checkpoint_index = pbft_checkpoint_state_multi_index_type{};
            }
        }

        void pbft_database::close() {


            fc::path checkpoints_db = checkpoints_dir / config::checkpoints_filename;
            std::ofstream c_out(checkpoints_db.generic_string().c_str(),
                    std::ios::out | std::ios::binary | std::ofstream::trunc);

            uint32_t num_records_in_checkpoint_db = checkpoint_index.size();
            fc::raw::pack(c_out, unsigned_int{num_records_in_checkpoint_db});

            if (!checkpoint_index.empty()) {
                for (const auto &s: checkpoint_index) {
                    fc::raw::pack(c_out, *s);
                }
            }

            fc::path pbft_db_dat = pbft_db_dir / config::pbftdb_filename;
            std::ofstream out(pbft_db_dat.generic_string().c_str(),
                    std::ios::out | std::ios::binary | std::ofstream::app);
            uint32_t num_records_in_db = index.size();
            fc::raw::pack(out, unsigned_int{num_records_in_db});

            if (!index.empty()) {
                for (const auto &s : index) {
                    fc::raw::pack(out, *s);
                }
            }
            index.clear();
            checkpoint_index.clear();
        }

        pbft_database::~pbft_database()
        {
            close();
        }


        void pbft_database::add_pbft_prepare(pbft_prepare &p) {

            if (!is_valid_prepare(p)) return;

            auto &by_block_id_index = index.get<by_block_id>();

            auto current = ctrl.fetch_block_state_by_id(p.block_id);

            while ((current) && (current->block_num > ctrl.last_irreversible_block_num())) {
                auto curr_itr = by_block_id_index.find(current->id);

                if (curr_itr == by_block_id_index.end()) {
                    try {
                        auto curr_ps = pbft_state{current->id, current->block_num, {p}};
                        auto curr_psp = make_shared<pbft_state>(curr_ps);
                        index.insert(curr_psp);
//                        ilog("insert prepare msg");
                    } catch (...) {
                        EOS_ASSERT(false, pbft_exception, "prepare insert failure: ${p}", ("p", p));
                    }
                } else {
                    auto prepares = (*curr_itr)->prepares;
                    auto p_itr = find_if(prepares.begin(), prepares.end(),
                            [&](const pbft_prepare &prep) { return prep.public_key == p.public_key && prep.view == p.view; });
                    if (p_itr == prepares.end()) {
                        by_block_id_index.modify(curr_itr, [&](const pbft_state_ptr &psp) {
                            psp->prepares.emplace_back(p);
                            std::sort(psp->prepares.begin(), psp->prepares.end(), less<>());
                        });
                    }
                }
                curr_itr = by_block_id_index.find(current->id);
                if (curr_itr == by_block_id_index.end()) return;

                auto prepares = (*curr_itr)->prepares;
                auto as = current->active_schedule.producers;
                flat_map<uint32_t,uint32_t> prepare_count;
                for (const auto &pre: prepares) {
                    if (prepare_count.find(pre.view) == prepare_count.end()) prepare_count[pre.view] = 0;
                }

                if (!(*curr_itr)->should_prepared) {
                    for (auto const &sp: as) {
                        for (auto const &pp: prepares) {
                            if (sp.block_signing_key == pp.public_key) prepare_count[pp.view] += 1;
                        }
                    }
                    for (auto const &e: prepare_count) {
                        if (e.second >= as.size() * 2 / 3 + 1) {
                            by_block_id_index.modify(curr_itr,
                                    [&](const pbft_state_ptr &psp) { psp->should_prepared = true; });
                        }
                    }
                }
                current = ctrl.fetch_block_state_by_id(current->prev());
            }
        }


        vector<pbft_prepare> pbft_database::send_and_add_pbft_prepare(const vector<pbft_prepare> &pv, uint32_t current_view) {

            auto head_block_num = ctrl.head_block_num();
            if (head_block_num <= 1) return vector<pbft_prepare>{};

            if (!pv.empty()) {
                for (auto p : pv) {
                    //change uuid, sign again, update cache, then emit
//                    auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
//                    p.uuid = uuid;
//                    p.producer_signature = ctrl.my_signature_providers()[p.public_key](p.digest());
                    emit(pbft_outgoing_prepare, p);
//                    ilog("retry pbft outgoing prepare msg: ${p} uuid: ${uuid}",("p", p.block_num)("uuid", p.uuid));
                }
                return vector<pbft_prepare>{};
            }  else {
                vector<pbft_prepare> new_pv;

                uint32_t high_water_mark_block_num = head_block_num;
                auto next_proposed_schedule_block_num = ctrl.get_global_properties().proposed_schedule_block_num;
                auto promoted_proposed_schedule_block_num = ctrl.last_promoted_proposed_schedule_block_num();
                auto lib = ctrl.last_irreversible_block_num();

                if (next_proposed_schedule_block_num && *next_proposed_schedule_block_num > lib) {
                    high_water_mark_block_num = std::min(head_block_num, *next_proposed_schedule_block_num);
                }

                if (promoted_proposed_schedule_block_num && promoted_proposed_schedule_block_num > lib) {
                    high_water_mark_block_num = std::min(high_water_mark_block_num, promoted_proposed_schedule_block_num);
                }

                if (high_water_mark_block_num <= lib) return vector<pbft_prepare>{};
                block_id_type high_water_mark_block_id = ctrl.get_block_id_for_num(high_water_mark_block_num);
                for (auto const &sp : ctrl.my_signature_providers()) {
//                    auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
                    auto p = pbft_prepare{current_view, high_water_mark_block_num, high_water_mark_block_id, sp.first, chain_id()};
                    p.producer_signature = sp.second(p.digest());
                    add_pbft_prepare(p);
                    emit(pbft_outgoing_prepare, p);
//                    ilog("pbft outgoing prepare msg: ${p} uuid: ${uuid}", ("p", p.block_num)("uuid", p.uuid));
                    new_pv.emplace_back(p);
                }
                return new_pv;
            }
        }

        bool pbft_database::should_prepared() {

            const auto &by_prepare_and_num_index = index.get<by_prepare_and_num>();
            auto itr = by_prepare_and_num_index.begin();
            if (itr == by_prepare_and_num_index.end()) return false;

            pbft_state_ptr psp = *itr;

            return (psp->should_prepared && (psp->block_num > ctrl.last_irreversible_block_num()));
        }

        bool pbft_database::is_valid_prepare(const pbft_prepare &p) {
//            if (!p.is_signature_valid()) return false;
            auto bs = ctrl.fetch_block_state_by_id(p.block_id);
            if (!bs) return false;
            auto as = bs->active_schedule.producers;
            auto ptr = find_if(as.begin(), as.end(), [&](const producer_key &k) { return k.block_signing_key == p.public_key; });
            if (ptr == as.end()) return false;
            return p.block_num == bs->block_num;
        }

        void pbft_database::add_pbft_commit(pbft_commit &c) {

            if (!is_valid_commit(c)) return;

            auto &by_block_id_index = index.get<by_block_id>();

            auto current = ctrl.fetch_block_state_by_id(c.block_id);

            while ((current) && (current->block_num > ctrl.last_irreversible_block_num())) {

                auto curr_itr = by_block_id_index.find(current->id);

                if (curr_itr == by_block_id_index.end()) {
                    try {
                        auto curr_ps = pbft_state{current->id, current->block_num, .commits={c}};
                        auto curr_psp = make_shared<pbft_state>(curr_ps);
                        index.insert(curr_psp);
//                        ilog("insert commit msg");
                    } catch (...) {
                        EOS_ASSERT(false, pbft_exception, "commit insert failure: ${c}", ("c", c));
                    }
                } else {
                    auto commits = (*curr_itr)->commits;
                    auto p_itr = find_if(commits.begin(), commits.end(),
                            [&](const pbft_commit &comm) { return comm.public_key == c.public_key && comm.view == c.view; });
                    if (p_itr == commits.end()) {
                        by_block_id_index.modify(curr_itr, [&](const pbft_state_ptr &psp) {
                            psp->commits.emplace_back(c);
//                            ilog("emplace commit msg");
                            std::sort(psp->commits.begin(), psp->commits.end(), less<>());
                        });
                    }
                }

                curr_itr = by_block_id_index.find(current->id);
                if (curr_itr == by_block_id_index.end()) return;

                auto commits = (*curr_itr)->commits;
                auto as = current->active_schedule;
                flat_map<uint32_t,uint32_t> commit_count;
                for (const auto &com: commits) {
                    if (commit_count.find(com.view) == commit_count.end()) commit_count[com.view] = 0;
                }
                
                if (!(*curr_itr)->should_committed) {
                    for (auto const &sp: as.producers) {
                        for (auto const &pc: commits) {
                            if (sp.block_signing_key == pc.public_key) commit_count[pc.view] += 1;
                        }
                    }
                    for (auto const &e: commit_count) {
                        if (e.second >= current->active_schedule.producers.size() * 2 / 3 + 1) {
                            by_block_id_index.modify(curr_itr,
                                    [&](const pbft_state_ptr &psp) { psp->should_committed = true; });
                        }
                    }
                }
                current = ctrl.fetch_block_state_by_id(current->prev());
            }
        }

        vector<pbft_commit> pbft_database::send_and_add_pbft_commit(const vector<pbft_commit> &cv, uint32_t current_view) {
            if (!cv.empty()) {
                for (auto c : cv) {
                    //change uuid, sign again, update cache, then emit
//                    auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
//                    c.uuid = uuid;
//                    c.producer_signature = ctrl.my_signature_providers()[c.public_key](c.digest());
                    emit(pbft_outgoing_commit, c);
//                    ilog("retry pbft outgoing commit msg: ${c} uuid: ${uuid}",("c", c.block_num)("uuid", c.uuid));
                }
                return vector<pbft_commit>{};
            } else {
                const auto &by_prepare_and_num_index = index.get<by_prepare_and_num>();
                auto itr = by_prepare_and_num_index.begin();
                if (itr == by_prepare_and_num_index.end()) {
                    return vector<pbft_commit>{};
                }
                vector<pbft_commit> new_cv;
                pbft_state_ptr psp = *itr;
                auto bs = ctrl.fork_db().get_block(psp->block_id);

                if (psp->should_prepared && (psp->block_num > ctrl.last_irreversible_block_num())) {

                    for (auto const &sp : ctrl.my_signature_providers()) {
//                        auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
                        auto c = pbft_commit{current_view, psp->block_num, psp->block_id, sp.first, chain_id()};
                        c.producer_signature = sp.second(c.digest());
                        add_pbft_commit(c);
                        emit(pbft_outgoing_commit, c);
//                        ilog("pbft outgoing commit msg: ${c}", ("c", c.block_num));
                        new_cv.emplace_back(c);
                    }
                }
                return new_cv;
            }
        }

        bool pbft_database::should_committed() {
            const auto &by_commit_and_num_index = index.get<by_commit_and_num>();
            auto itr = by_commit_and_num_index.begin();
            if (itr == by_commit_and_num_index.end()) return false;
            pbft_state_ptr psp = *itr;

            return (psp->should_committed && (psp->block_num > (ctrl.last_irreversible_block_num())));
        }

        uint32_t pbft_database::get_committed_view() {
            uint32_t new_view = 0;
            if (!should_committed()) return new_view;

            const auto &by_commit_and_num_index = index.get<by_commit_and_num>();
            auto itr = by_commit_and_num_index.begin();
            pbft_state_ptr psp = *itr;
            auto blk_state = ctrl.fetch_block_state_by_id((*itr)->block_id);
            if (!blk_state) return new_view;
            auto as = blk_state->active_schedule.producers;

            auto commits = (*itr)->commits;

            flat_map<uint32_t,uint32_t> commit_count;
            for (const auto &com: commits) {
                if (commit_count.find(com.view) == commit_count.end()) {
                    commit_count[com.view] = 1;
                } else {
                    commit_count[com.view] += 1;
                }
            }

            for (auto const &e: commit_count) {
                if (e.second >= as.size() * 2 / 3 + 1 && e.first > new_view) {
                    new_view = e.first;
                }
            }
//            wlog("committed new view is ${nv}", ("nv", new_view));
            return new_view;
        }

        bool pbft_database::is_valid_commit(const pbft_commit &c) {
//            if (!c.is_signature_valid()) return false;
            auto bs = ctrl.fetch_block_state_by_id(c.block_id);
            if (!bs) return false;
            auto as = bs->active_schedule.producers;
            auto ptr = find_if(as.begin(), as.end(), [&](const producer_key &k) { return k.block_signing_key == c.public_key; });
            if (ptr == as.end()) return false;
            return c.block_num == bs->block_num;
        }

        void pbft_database::commit_local() {
            const auto &by_commit_and_num_index = index.get<by_commit_and_num>();
            auto itr = by_commit_and_num_index.begin();
            if (itr == by_commit_and_num_index.end()) return;

            pbft_state_ptr psp = *itr;

            ctrl.pbft_commit_local(psp->block_id);
        }

        bool pbft_database::pending_pbft_lib() {
            return ctrl.pending_pbft_lib();
        }

        void pbft_database::add_pbft_view_change(pbft_view_change &vc) {
            if (!is_valid_view_change(vc)) return;

            auto active_bps = lib_active_producers().producers;

            auto &by_view_index = view_state_index.get<by_view>();
            auto itr = by_view_index.find(vc.view);
            if (itr == by_view_index.end()) {
                auto vs = pbft_view_state{vc.view, .view_changes={vc}};
                auto vsp = make_shared<pbft_view_state>(vs);
                view_state_index.insert(vsp);
//                ilog("insert view change msg");
            } else {
                auto pvs = (*itr);
                auto view_changes = pvs->view_changes;
                auto p_itr = find_if(view_changes.begin(), view_changes.end(),
                        [&](const pbft_view_change &existed) { return existed.public_key == vc.public_key; });
                if (p_itr == view_changes.end()) {
                    by_view_index.modify(itr, [&](const pbft_view_state_ptr &pvsp) {
//                        ilog("emplace view change msg");
                        pvsp->view_changes.emplace_back(vc);
                    });
                }
            }

            itr = by_view_index.find(vc.view);
            if (itr == by_view_index.end()) return;
//            wlog("view change state === ${v} === ${s}", ("v", (*itr)->view_changes)("s", (*itr)->should_view_changed));
            auto vc_count = 0;
            if (!(*itr)->should_view_changed) {
                for (auto const &sp: active_bps) {
                    for (auto const &pp: (*itr)->view_changes) {
                        if (sp.block_signing_key == pp.public_key) vc_count += 1;
                    }
                }
                if (vc_count >= active_bps.size() * 2 / 3 + 1) {
                    by_view_index.modify(itr, [&](const pbft_view_state_ptr &pvsp) {
                        pvsp->should_view_changed = true;
//                        wlog("view ${v} is potential new view", ("v", (*itr)->view));
                    });
                }
            }
        }

        void pbft_database::set_pbft_prepared_block_id(optional<block_id_type> bid){
            ctrl.set_pbft_prepared_block_id(bid);
        }

        uint32_t pbft_database::should_view_change() {
            uint32_t nv = 0;
            auto &by_view_index = view_state_index.get<by_view>();
            auto itr = by_view_index.begin();
            if (itr == by_view_index.end()) return nv;

            while (itr != by_view_index.end()) {
                auto active_bps = lib_active_producers().producers;
                auto vc_count = 0;
                auto pvs = (*itr);

                for (auto const &bp: active_bps) {
                    for (auto const &pp: pvs->view_changes) {
                        if (bp.block_signing_key == pp.public_key) vc_count += 1;
                    }
                }
                //if contains self or view_change >= f+1, transit to view_change and send view change
                if (vc_count >= active_bps.size() / 3 + 1) {
                    nv = pvs->view;
                    break;
                }
                ++itr;
            }
            return nv;
        }

        vector<pbft_view_change> pbft_database::send_and_add_pbft_view_change(
                const vector<pbft_view_change> &vcv,
                const vector<pbft_prepared_certificate> &ppc,
                const vector<pbft_committed_certificate> &pcc,
                uint32_t new_view)
        {
            if (!vcv.empty()) {
                for (auto vc : vcv) {
                    //change uuid, sign again, update cache, then emit
//                    auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
//                    vc.uuid = uuid;
//                    vc.producer_signature = ctrl.my_signature_providers()[vc.public_key](vc.digest());
//                    ilog("retry pbft outgoing view change msg: ${v}",("v", vc.view));
                    emit(pbft_outgoing_view_change, vc);
                }
                return vector<pbft_view_change>{};
            } else {
                vector<pbft_view_change> new_vcv;

                for (auto const &my_sp : ctrl.my_signature_providers()) {
                    auto ppc_ptr = find_if( ppc.begin(), ppc.end(),
                            [&](const pbft_prepared_certificate &v) { return v.public_key == my_sp.first; });
                    auto pcc_ptr = find_if( pcc.begin(), pcc.end(),
                            [&](const pbft_committed_certificate &v) { return v.public_key == my_sp.first; });

                    auto my_ppc = pbft_prepared_certificate{};
                    auto my_pcc = pbft_committed_certificate{};
                    if (ppc_ptr != ppc.end()) my_ppc = *ppc_ptr;
                    if (pcc_ptr != pcc.end()) my_pcc = *pcc_ptr;

                    auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
                    auto vc = pbft_view_change{new_view, my_ppc, my_pcc, my_sp.first, chain_id()};
                    vc.producer_signature = my_sp.second(vc.digest());
//                    ilog("starting new round of view change: ${nv}", ("nv", vc.view));
                    emit(pbft_outgoing_view_change, vc);
                    add_pbft_view_change(vc);
                    new_vcv.emplace_back(vc);
                }
                return new_vcv;
            }
        }


        bool pbft_database::should_new_view(const uint32_t target_view) {
            auto &by_view_index = view_state_index.get<by_view>();
            auto itr = by_view_index.find(target_view);
            if (itr == by_view_index.end()) return false;
            return (*itr)->should_view_changed;
        }

        uint32_t pbft_database::get_proposed_new_view_num() {
            auto &by_count_and_view_index = view_state_index.get<by_count_and_view>();
            auto itr = by_count_and_view_index.begin();
            if (itr == by_count_and_view_index.end() || !(*itr)->should_view_changed) return 0;
            return (*itr)->view;
        }


        bool pbft_database::is_new_primary(const uint32_t target_view) {

            auto primary_key = get_new_view_primary_key(target_view);

            if (primary_key == public_key_type{}) return false;
            auto sps = ctrl.my_signature_providers();
            auto sp_itr = sps.find(primary_key);
            return sp_itr != sps.end();
        }

        void pbft_database::prune_view_change_index() {
            view_state_index.clear();
        }

        pbft_new_view pbft_database::send_pbft_new_view(
                const vector<pbft_view_changed_certificate> &vcc,
                uint32_t current_view)
        {

            auto primary_key = get_new_view_primary_key(current_view);
            if (!is_new_primary(current_view)) return pbft_new_view{};

            //`sp_itr` is not possible to be the end iterator, since it's already been checked in `is_new_primary`.
            auto my_sps = ctrl.my_signature_providers();
            auto sp_itr = my_sps.find(primary_key);

            auto vcc_ptr = find_if( vcc.begin(), vcc.end(),
                    [&](const pbft_view_changed_certificate &v) { return v.public_key == primary_key; });

            if (vcc_ptr == vcc.end()) {
                wlog("can not find primary's view changed certificate when trying to send new view");
                return pbft_new_view{};
            }

            auto highest_ppc = pbft_prepared_certificate{};
            auto highest_pcc = pbft_committed_certificate{};

            for (const auto &vc: vcc_ptr->view_changes) {
                if (vc.prepared.block_num > highest_ppc.block_num
                && is_valid_prepared_certificate(vc.prepared)) {
                    highest_ppc = vc.prepared;
                }
                if (vc.committed.block_num > highest_pcc.block_num
                && is_valid_committed_certificate(vc.committed)) {
                    highest_pcc = vc.committed;
                }
            }

            auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
            auto nv = pbft_new_view{current_view, .prepared=highest_ppc, .committed=highest_pcc, .view_changed=*vcc_ptr, .public_key=sp_itr->first, .chain_id=chain_id()};
            nv.producer_signature = sp_itr->second(nv.digest());
            emit(pbft_outgoing_new_view, nv);
            return nv;
        }

        vector<pbft_prepared_certificate> pbft_database::generate_prepared_certificate() {
            auto ppc = vector<pbft_prepared_certificate>{};

            const auto &by_prepare_and_num_index = index.get<by_prepare_and_num>();
            auto itr = by_prepare_and_num_index.begin();
            if (itr == by_prepare_and_num_index.end()) return vector<pbft_prepared_certificate>{};
            pbft_state_ptr psp = *itr;

            auto prepared_block_state = ctrl.fetch_block_state_by_id(psp->block_id);
            if (!prepared_block_state) return vector<pbft_prepared_certificate>{};

            auto as = prepared_block_state->active_schedule.producers;
            if (psp->should_prepared && (psp->block_num > (ctrl.last_irreversible_block_num()))) {
                for (auto const &my_sp : ctrl.my_signature_providers()) {
                    auto prepares = psp->prepares;
                    auto valid_prepares = vector<pbft_prepare>{};

                    flat_map<uint32_t,uint32_t> prepare_count;
                    flat_map<uint32_t,vector<pbft_prepare>> prepare_msg;

                    for (const auto &pre: prepares) {
                        if (prepare_count.find(pre.view) == prepare_count.end()) prepare_count[pre.view] = 0;
                        prepare_msg[pre.view].push_back(pre);
                    }

                    for (auto const &sp: as) {
                        for (auto const &pp: prepares) {
                            if (sp.block_signing_key == pp.public_key) prepare_count[pp.view] += 1;
                        }
                    }

                    for (auto const &e: prepare_count) {
                        if (e.second >= as.size() * 2 / 3 + 1) {
                            valid_prepares = prepare_msg[e.first];
                        }
                    }
                    if (valid_prepares.empty()) {
                        wlog("no enough valid prepares for a prepared block, my prepares: ${p}", ("p", prepares));
                        return vector<pbft_prepared_certificate>{};
                    };

                    auto pc = pbft_prepared_certificate{psp->block_id, psp->block_num, valid_prepares, my_sp.first};
                    pc.producer_signature = my_sp.second(pc.digest());
                    ppc.emplace_back(pc);
                }
                return ppc;
            } else return vector<pbft_prepared_certificate>{};
        }

        vector<pbft_committed_certificate> pbft_database::generate_committed_certificate() {
            auto pcc = vector<pbft_committed_certificate>{};

            const auto &by_commit_and_num_index = index.get<by_commit_and_num>();
            auto itr = by_commit_and_num_index.begin();
            if (itr == by_commit_and_num_index.end()) return vector<pbft_committed_certificate>{};
            pbft_state_ptr psp = *itr;

            auto committed_block_state = ctrl.fetch_block_state_by_id(psp->block_id);
            if (!committed_block_state) return vector<pbft_committed_certificate>{};
//            ilog("try to fetch block state");
            auto as = committed_block_state->active_schedule.producers;
//            ilog("fetched block state");
            if (psp->should_committed && (psp->block_num >= (ctrl.last_irreversible_block_num()))) {
                for (auto const &my_sp : ctrl.my_signature_providers()) {
                    auto commits = psp->commits;
                    auto valid_commits = vector<pbft_commit>{};

                    flat_map<uint32_t,uint32_t> commit_count;
                    flat_map<uint32_t,vector<pbft_commit>> commit_msg;

                    for (const auto &com: commits) {
                        if (commit_count.find(com.view) == commit_count.end()) commit_count[com.view] = 0;
                        commit_msg[com.view].push_back(com);
                    }
                    for (auto const &sp: as) {
                        for (auto const &pc: commits) {
                            if (sp.block_signing_key == pc.public_key) commit_count[pc.view] += 1;
                        }
                    }

                    for (auto const &e: commit_count) {
                        if (e.second >= as.size() * 2 / 3 + 1) {
                            valid_commits = commit_msg[e.first];
                        }
                    }
                    if (valid_commits.empty()) {
                        wlog("no enough valid commits for a committed block, my commits: ${c}", ("c", commits));
                        return vector<pbft_committed_certificate>{};
                    };
                    auto cc = pbft_committed_certificate{psp->block_id, psp->block_num, valid_commits, my_sp.first};
                    cc.producer_signature = my_sp.second(cc.digest());
                    pcc.emplace_back(cc);
                }
                return pcc;
            } else return vector<pbft_committed_certificate>{};
        }

        vector<pbft_view_changed_certificate> pbft_database::generate_view_changed_certificate() {
            auto vcc = vector<pbft_view_changed_certificate>{};

            auto &by_count_and_view_index = view_state_index.get<by_count_and_view>();
            auto itr = by_count_and_view_index.begin();
            if (itr == by_count_and_view_index.end()) return vector<pbft_view_changed_certificate>{};
            auto active_bps = lib_active_producers().producers;

            auto pvs = *itr;

            if (pvs->should_view_changed) {
                for (auto const &my_sp : ctrl.my_signature_providers()) {
                    auto pc = pbft_view_changed_certificate{pvs->view, pvs->view_changes, my_sp.first};
                    pc.producer_signature = my_sp.second(pc.digest());
                    vcc.emplace_back(pc);
                }
                return vcc;
            } else return vector<pbft_view_changed_certificate>{};
        }

        bool pbft_database::is_valid_prepared_certificate(const eosio::chain::pbft_prepared_certificate &certificate) {
            // an empty certificate is valid since it acts as a null digest in pbft.
            if (certificate == pbft_prepared_certificate{}) return true;
            //all signatures should be valid
            auto valid = true;
//            valid &= certificate.is_signature_valid();
            for (auto const &p : certificate.prepares) {
                valid &= is_valid_prepare(p);
                if (!valid) return false;
            }
//            ilog("prepare signature valid!");

            auto cert_num = certificate.block_num;
            auto cert_bs = ctrl.fetch_block_state_by_number(cert_num);
            auto producer_schedule = lib_active_producers();
            if ( cert_num > 0 && cert_bs) {
                producer_schedule = cert_bs->active_schedule;
            }

            auto bp_threshold = producer_schedule.producers.size() * 2 / 3 + 1;

            {
                //validate prepare
                vector<block_info> prepare_infos(certificate.prepares.size());
                for (auto const &p : certificate.prepares) {
                    prepare_infos.push_back(block_info{p.block_id, p.block_num});
                }

                auto prepare_forks = fetch_fork_from(prepare_infos);
                vector<block_info> longest_fork;
                for (auto const &f : prepare_forks) {
                    if (f.size() > longest_fork.size()) {
                        longest_fork = f;
                    }
                }
                if (longest_fork.size() < bp_threshold) return false;
//                ilog("prepare longest fork valid!");

                auto calculated_block_info = longest_fork[bp_threshold-1];

                auto current = ctrl.fetch_block_by_id(calculated_block_info.block_id);
                while (current) {
                    if (certificate.block_id == current->id() && certificate.block_num == current->block_num()) return true;
                    current = ctrl.fetch_block_by_id(current->previous);
                }
                return false;
//                ilog("prepare block id and num valid!");
            }
        }

        bool pbft_database::is_valid_committed_certificate(const pbft_committed_certificate &certificate) {
            //null certificate is valid
            if (certificate == pbft_committed_certificate{}) return true;

            //lib certificate is valid
            if (certificate.block_num == ctrl.last_irreversible_block_num()
            && certificate.block_id == ctrl.last_irreversible_block_id()) return true;

            auto valid = true;
//            valid &= certificate.is_signature_valid();
            for (auto const &c : certificate.commits) {
                valid &= is_valid_commit(c);
                if (!valid) return false;
            }

//            ilog("commit signature valid!");

            auto cert_num = certificate.block_num;
            auto cert_bs = ctrl.fetch_block_state_by_number(cert_num);
            auto producer_schedule = lib_active_producers();
            if ( cert_num > 0 && cert_bs) {
                producer_schedule = cert_bs->active_schedule;
            }

            auto bp_threshold = producer_schedule.producers.size() * 2 / 3 + 1;

            {
                //validate commit
                vector<block_info> commit_infos(certificate.commits.size());
                for (auto const &c : certificate.commits) {
                    commit_infos.push_back(block_info{c.block_id, c.block_num});
                }

                auto commit_forks = fetch_fork_from(commit_infos);
                vector<block_info> longest_fork;
                for (auto const &f : commit_forks) {
                    if (f.size() > longest_fork.size()) {
                        longest_fork = f;
                    }
                }
                if (longest_fork.size() < bp_threshold) return false;
//                ilog("commit longest fork valid!");

                auto calculated_block_info = longest_fork[bp_threshold-1];

                auto current = ctrl.fetch_block_by_id(calculated_block_info.block_id);
                while (current) {
                    if (certificate.block_id == current->id() && certificate.block_num == current->block_num()) return true;
                    current = ctrl.fetch_block_by_id(current->previous);
                }
                return false;
//                ilog("commit block id and num valid!");
            }
        }

        bool pbft_database::is_valid_view_change(const pbft_view_change &certificate) {
            //all signatures should be valid

//            return certificate.is_signature_valid()
//                   &&
            return is_valid_prepared_certificate(certificate.prepared)
                   && is_valid_committed_certificate(certificate.committed);
        }


        bool pbft_database::is_valid_new_view(const pbft_new_view &certificate) {
            //all signatures should be valid
            auto valid = is_valid_prepared_certificate(certificate.prepared)
                    && is_valid_committed_certificate(certificate.committed);
//                    && certificate.view_changed.is_signature_valid()
//                    && certificate.is_signature_valid();

            for (const auto &vc: certificate.view_changed.view_changes) {
                valid &= is_valid_view_change(vc);
                if (!valid) return false;
                auto v = vc;
                add_pbft_view_change(v);
            }

            if (!should_new_view(certificate.view)) return false;

//            ilog("valid view changed certificate");

            auto highest_ppc = pbft_prepared_certificate{};
            auto highest_pcc = pbft_committed_certificate{};

            for (const auto &vc: certificate.view_changed.view_changes) {
                if (vc.prepared.block_num > highest_ppc.block_num
                    && is_valid_prepared_certificate(vc.prepared)) {
                    highest_ppc = vc.prepared;
                }
                if (vc.committed.block_num > highest_pcc.block_num
                    && is_valid_committed_certificate(vc.committed)) {
                    highest_pcc = vc.committed;
                }
            }

            return highest_ppc == certificate.prepared && highest_pcc == certificate.committed;
        }

        vector<vector<block_info>> pbft_database::fetch_fork_from(const vector<block_info> block_infos) {
            auto bi = block_infos;

            vector<vector<block_info>> result;
            if (bi.empty()) {
                return result;
            }
            if (bi.size() == 1) {
                result.emplace_back(initializer_list<block_info>{bi.front()});
                return result;
            }

            sort(bi.begin(), bi.end(),
                 [](const block_info &a, const block_info &b) -> bool { return a.block_num > b.block_num; });

            while (!bi.empty()) {
                auto fork = fetch_first_fork_from(bi);
                if (!fork.empty()) {
                    result.emplace_back(fork);
                }
            }
            return result;
        }

        vector<block_info> pbft_database::fetch_first_fork_from(vector<block_info> &bi) {
            vector<block_info> result;
            if (bi.empty()) {
                return result;
            }
            if (bi.size() == 1) {
                result.emplace_back(bi.front());
                bi.clear();
                return result;
            }
            //bi should be sorted desc
            auto high = bi.front().block_num;
            auto low = bi.back().block_num;

            auto id = bi.front().block_id;
            auto num = bi.front().block_num;
            while (num <= high && num >= low && !bi.empty()) {
                auto b = ctrl.fetch_block_by_id(id);

                for (auto it = bi.begin(); it != bi.end();) {
                    if (it->block_id == id) {
                        if (b) {
                            //add to result only if b exist
                            result.emplace_back((*it));
                        }
                        it = bi.erase(it);
                    } else {
                        it++;
                    }
                }
                if (b) {
                    id = b->previous;
                    num--;
                } else {
                    break;
                }
            }

            return result;
        }

        pbft_stable_checkpoint pbft_database::get_stable_checkpoint_by_id(const block_id_type &block_id) {

            const auto &by_block = checkpoint_index.get<by_block_id>();
            auto itr = by_block.find(block_id);
            if (itr == by_block.end()) return pbft_stable_checkpoint{};

            auto cpp = *itr;

            if (cpp->is_stable) {
                if (ctrl.my_signature_providers().empty()) return pbft_stable_checkpoint{};
                auto psc = pbft_stable_checkpoint{cpp->block_num, cpp->block_id, cpp->checkpoints, ctrl.my_signature_providers().begin()->first, .chain_id=chain_id() };
                psc.producer_signature = ctrl.my_signature_providers().begin()->second(psc.digest());
                return psc;
            } else return pbft_stable_checkpoint{};
        }

        block_num_type pbft_database::cal_latest_possible_stable_checkpoint_block_num() const {
            auto lscb_num = ctrl.last_stable_checkpoint_block_num();

            const auto &by_blk_num = checkpoint_index.get<by_stable_and_num>();
            auto itr = by_blk_num.lower_bound(lscb_num);
            if (itr == by_blk_num.end()) return block_num_type{};

            while (itr != by_blk_num.end()) {
                if ( (*itr)->is_stable && ctrl.fetch_block_state_by_id((*itr)->block_id)) {
                    auto lib = ctrl.fetch_block_state_by_number(ctrl.last_irreversible_block_num());

                    auto head_checkpoint_schedule = ctrl.fetch_block_state_by_id(
                            (*itr)->block_id)->active_schedule;

                    auto current_schedule = lib_active_producers();
                    auto new_schedule = lib_active_producers();

                    if (lib) {
                        current_schedule = lib->active_schedule;
                        new_schedule = lib->pending_schedule;
                    }
//                    wlog("head checkpoint schedule version ${c}, lib_sv: ${l}, new_sv: ${n}",
//                            ("c", head_checkpoint_schedule)("l", current_schedule)("n", new_schedule));

                    if ((*itr)->is_stable
                    && (head_checkpoint_schedule == current_schedule || head_checkpoint_schedule == new_schedule)) {
                        lscb_num = (*itr)->block_num;
                    }
                }
                ++itr;
            }
            return lscb_num;
        }

        vector<pbft_checkpoint> pbft_database::generate_and_add_pbft_checkpoint() {
            const auto &by_commit_and_num_index = index.get<by_commit_and_num>();
            auto itr = by_commit_and_num_index.begin();
            if (itr == by_commit_and_num_index.end()) return vector<pbft_checkpoint>{};

            pbft_state_ptr psp = (*itr);
            auto new_pc = vector<pbft_checkpoint>{};

            vector<block_num_type> pending_checkpoint_block_num;

            block_num_type my_latest_checkpoint = 0;

            auto checkpoint = [&]( const  block_num_type& in ) {

                return in % 6 == 1
                || (in >= ctrl.last_proposed_schedule_block_num() && in <= ctrl.last_promoted_proposed_schedule_block_num());
            };

            for (auto i = psp->block_num; i > std::max(ctrl.last_stable_checkpoint_block_num(), static_cast<uint32_t>(1)); --i) {
                if (checkpoint(i)) {
                    my_latest_checkpoint = max(i, my_latest_checkpoint);
                    auto &by_block = checkpoint_index.get<by_block_id>();
                    auto c_itr = by_block.find(ctrl.get_block_id_for_num(i));
                    if (c_itr == by_block.end()) {
                        pending_checkpoint_block_num.emplace_back(i);
                    } else {
                        auto checkpoints = (*c_itr)->checkpoints;
                        bool contains_mine = false;
                        for (auto const &my_sp : ctrl.my_signature_providers()) {
                            auto p_itr = find_if(checkpoints.begin(), checkpoints.end(),
                                    [&](const pbft_checkpoint &ext) { return ext.public_key == my_sp.first; });
                            if (p_itr != checkpoints.end()) contains_mine = true;
                        }
                        if (!contains_mine) {
                            pending_checkpoint_block_num.emplace_back(i);
                        }
                    }
                }
            }

            if (!pending_checkpoint_block_num.empty()) {
                for (auto h: pending_checkpoint_block_num) {
                    for (auto const &my_sp : ctrl.my_signature_providers()) {
//                        auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
                        auto cp = pbft_checkpoint{h, ctrl.get_block_id_for_num(h), my_sp.first, .chain_id=chain_id()};
                        cp.producer_signature = my_sp.second(cp.digest());
//                        ilog("generating checkpoint: ${cp}", ("cp", cp.block_num));
                        add_pbft_checkpoint(cp);
                        new_pc.emplace_back(cp);
                    }
                }
                //update checkpoint immediately.
                send_pbft_checkpoint(new_pc);
            } else if (my_latest_checkpoint > 1) {
                auto lscb_id = ctrl.get_block_id_for_num(my_latest_checkpoint);
//                ilog("latest checkpoint: ${h}", ("h", my_latest_checkpoint));
                auto &by_block = checkpoint_index.get<by_block_id>();
                auto h_itr = by_block.find(lscb_id);
                if (h_itr != by_block.end()) {
                    auto checkpoints = (*h_itr)->checkpoints;
                    for (auto const &my_sp : ctrl.my_signature_providers()) {
                        for (auto const &cp: checkpoints) {
                            if (my_sp.first == cp.public_key) {
//                                ilog("retry latest checkpoint: ${h}", ("h", cp.block_num));
                                new_pc.emplace_back(cp);
                            }
                        }
                    }
                }
            }

            return new_pc;
        }

        void pbft_database::add_pbft_checkpoint(pbft_checkpoint &cp) {

            if (!is_valid_checkpoint(cp)) return;

            auto lscb_num = ctrl.last_stable_checkpoint_block_num();
            if (cp.block_num <= lscb_num) return;
            if (cp.block_num > ctrl.head_block_num()) return;

            auto cp_block_state = ctrl.fetch_block_state_by_number(cp.block_num);
            if (!cp_block_state) return;
            auto active_bps = cp_block_state->active_schedule.producers;
            auto checkpoint_count = count_if(active_bps.begin(), active_bps.end(), [&](const producer_key &p) {
                return p.block_signing_key == cp.public_key; });
            if (checkpoint_count == 0) return;

            auto &by_block = checkpoint_index.get<by_block_id>();
            auto itr = by_block.find(cp.block_id);
            if (itr == by_block.end()) {
                auto cs = pbft_checkpoint_state{cp.block_id, cp.block_num, .checkpoints={cp}};
                auto csp = make_shared<pbft_checkpoint_state>(cs);
                checkpoint_index.insert(csp);
                itr = by_block.find(cp.block_id);
            } else {
                auto csp = (*itr);
                auto checkpoints = csp->checkpoints;
                auto p_itr = find_if(checkpoints.begin(), checkpoints.end(),
                        [&](const pbft_checkpoint &existed) { return existed.public_key == cp.public_key; });
                if (p_itr == checkpoints.end()) {
                    by_block.modify(itr, [&](const pbft_checkpoint_state_ptr &pcp) {
                        csp->checkpoints.emplace_back(cp);
                    });
                }
            }

            auto csp = (*itr);
            auto cp_count = 0;
            if (!csp->is_stable) {
                for (auto const &sp: active_bps) {
                    for (auto const &pp: csp->checkpoints) {
                        if (sp.block_signing_key == pp.public_key) cp_count += 1;
                    }
                }
                if (cp_count >= active_bps.size() * 2 / 3 + 1) {
                    by_block.modify(itr, [&](const pbft_checkpoint_state_ptr &pcp) { csp->is_stable = true; });
                }
            }

            auto pending_num = cal_latest_possible_stable_checkpoint_block_num();
            if (pending_num > lscb_num) {
                auto pending_id = ctrl.get_block_id_for_num(pending_num);
                ctrl.set_pbft_latest_checkpoint(pending_id);
                if (ctrl.last_irreversible_block_num() < pending_num) ctrl.pbft_commit_local(pending_id);
                const auto &pbft_state_index = index.get<by_block_id>();
                auto pitr = pbft_state_index.find(pending_id);
                if (pitr != pbft_state_index.end()) {
                    prune(*pitr);
                }
            }
        }

        void pbft_database::send_pbft_checkpoint(const vector<pbft_checkpoint> &cps) {
            if (cps.empty()) return;
            for (auto const &cp: cps) {
                emit(pbft_outgoing_checkpoint, cp);
//                    ilog("sending pbft checkpoint at ${h}", ("h", cp.block_num));
            }
        }


        bool pbft_database::is_valid_checkpoint(const pbft_checkpoint &cp) {
//            if (!cp.is_signature_valid()) return false;

            auto bs = ctrl.fetch_block_state_by_id(cp.block_id);
            if (bs) {
                auto active_bps = bs->active_schedule.producers;
                for (const auto &bp: active_bps) {
                    if (bp.block_signing_key == cp.public_key) return true;
                }
            }
            return false;
        }

        bool pbft_database::is_valid_stable_checkpoint(const pbft_stable_checkpoint &scp) {

            bool valid = true;
//            valid = scp.is_signature_valid();
//            if (!valid) return false;
            for (const auto &c: scp.checkpoints) {
                valid &= c.block_id == scp.block_id && c.block_num == scp.block_num;
                if (!valid) return false;
            }
            return valid;
        }

        bool pbft_database::should_send_pbft_msg() {

            //use last_stable_checkpoint producer schedule
            auto lscb_num = ctrl.last_stable_checkpoint_block_num();

            const auto &by_blk_num = index.get<by_num>();
            auto itr = by_blk_num.lower_bound(lscb_num);
            if (itr == by_blk_num.end()) {
                for (auto const &bp: lib_active_producers().producers) {
                    for (auto const &my: ctrl.my_signature_providers()) {
                        if (bp.block_signing_key == my.first) {
                            return true;
                        }
                    }
                }
                return false;
            }

            producer_schedule_type as;

            for (; itr != by_blk_num.end(); ++itr) {
                auto bs = ctrl.fetch_block_state_by_number((*itr)->block_num);
                if (bs && bs->active_schedule != as) {
                    as = bs->active_schedule;
                    for (auto const &bp: as.producers) {
                        for (auto const &my: ctrl.my_signature_providers()) {
                            if (bp.block_signing_key == my.first) {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        public_key_type pbft_database::get_new_view_primary_key(const uint32_t target_view) {

            auto active_bps = lib_active_producers().producers;
            if (active_bps.empty()) return public_key_type{};

            return active_bps[target_view % active_bps.size()].block_signing_key;
        }

        producer_schedule_type pbft_database::lib_active_producers() const {
            auto lib_num = ctrl.last_irreversible_block_num();
            if (lib_num == 0) return ctrl.initial_schedule();
            auto lib_state = ctrl.fetch_block_state_by_number(lib_num);

            if  (lib_num == ctrl.last_promoted_proposed_schedule_block_num())
                return  lib_state->pending_schedule;
            return lib_state->active_schedule;
        }

        chain_id_type pbft_database::chain_id() {
            return ctrl.get_chain_id();
        }


        void pbft_database::set(pbft_state_ptr s) {
            auto result = index.insert(s);

            EOS_ASSERT(result.second, pbft_exception,
                       "unable to insert pbft state, duplicate state detected");
        }

        void pbft_database::set(pbft_checkpoint_state_ptr s) {
            auto result = checkpoint_index.insert(s);

            EOS_ASSERT(result.second, pbft_exception,
                       "unable to insert pbft checkpoint index, duplicate state detected");
        }

        void pbft_database::prune( const pbft_state_ptr& h ) {
            auto num = h->block_num;

            auto& by_bn =index.get<by_num>();
            auto bni = by_bn.begin();
            while( bni != by_bn.end() && (*bni)->block_num < num ) {
                prune( *bni );
                bni = by_bn.begin();
            }

            auto itr = index.find( h->block_id );
            if( itr != index.end() ) {
                index.erase(itr);
            }
        }

        template<typename Signal, typename Arg>
        void pbft_database::emit( const Signal& s, Arg&& a ) {
            try {
                s(std::forward<Arg>(a));
            } catch (boost::interprocess::bad_alloc& e) {
                wlog( "bad alloc" );
                throw e;
            } catch ( controller_emit_signal_exception& e ) {
                wlog( "${details}", ("details", e.to_detail_string()) );
                throw e;
            } catch ( fc::exception& e ) {
                wlog( "${details}", ("details", e.to_detail_string()) );
            } catch ( ... ) {
                wlog( "signal handler threw exception" );
            }
        }
    }
}