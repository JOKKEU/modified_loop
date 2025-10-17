#include "loop.h"


#ifdef CONFIG_BLK_CGROUP
inline int queue_on_root_worker(struct cgroup_subsys_state *css)
{
	return !css || css == blkcg_root_css;
}
#else
inline int queue_on_root_worker(struct cgroup_subsys_state *css)
{
	return !css;
}
#endif // CONFIG_BLK_CGROUP


void loop_set_timer(struct loop_device *lo)
{
	LOG(KERN_INFO, "\n");
	timer_reduce(&lo->timer, jiffies + LOOP_IDLE_WORKER_TIMEOUT);
}

void loop_process_work(struct loop_worker *worker, struct list_head *cmd_list, struct loop_device *lo)
{
	//LOG(KERN_INFO, "\n");
	int orig_flags = current->flags;
	struct loop_cmd *cmd;

	current->flags |= PF_LOCAL_THROTTLE | PF_MEMALLOC_NOIO;
	spin_lock_irq(&lo->lo_work_lock);
	while (!list_empty(cmd_list))
	{
		cmd = container_of(cmd_list->next, struct loop_cmd, list_entry);
		list_del(cmd_list->next);
		spin_unlock_irq(&lo->lo_work_lock);

		loop_handle_cmd(cmd);
		cond_resched();

		spin_lock_irq(&lo->lo_work_lock);
	}

	/*
	 * We only add to the idle list if there are no pending cmds
	 * *and* the worker will not run again which ensures that it
	 * is safe to free any worker on the idle list
	 */
	if (worker && !work_pending(&worker->work))
	{
		worker->last_ran_at = jiffies;
		list_add_tail(&worker->idle_list, &lo->idle_worker_list);
		loop_set_timer(lo);
	}
	spin_unlock_irq(&lo->lo_work_lock);
	current->flags = orig_flags;
}

void loop_workfn(struct work_struct *work)
{
	//LOG(KERN_INFO, "\n");
	struct loop_worker *worker =
	container_of(work, struct loop_worker, work);
	loop_process_work(worker, &worker->cmd_list, worker->lo);
}

void loop_rootcg_workfn(struct work_struct *work)
{
	//LOG(KERN_INFO, "\n");
	struct loop_device *lo =
	container_of(work, struct loop_device, rootcg_work);
	loop_process_work(NULL, &lo->rootcg_cmd_list, lo);
}

void loop_free_idle_workers(struct timer_list *timer)
{
	//LOG(KERN_INFO, "\n");
	struct loop_device *lo = container_of(timer, struct loop_device, timer);
	struct loop_worker *pos, *worker;

	spin_lock_irq(&lo->lo_work_lock);
	list_for_each_entry_safe(worker, pos, &lo->idle_worker_list,
				 idle_list) {
		if (time_is_after_jiffies(worker->last_ran_at +
			LOOP_IDLE_WORKER_TIMEOUT))
			break;
		list_del(&worker->idle_list);
		rb_erase(&worker->rb_node, &lo->worker_tree);
		css_put(worker->blkcg_css);
		kfree(worker);
				 }
				 if (!list_empty(&lo->idle_worker_list))
					 loop_set_timer(lo);
	spin_unlock_irq(&lo->lo_work_lock);
}

void loop_queue_work(struct loop_device *lo, struct loop_cmd *cmd)
{
	//LOG(KERN_INFO, "\n");
	struct rb_node **node = &(lo->worker_tree.rb_node), *parent = NULL;
	struct loop_worker *cur_worker, *worker = NULL;
	struct work_struct *work;
	struct list_head *cmd_list;

	spin_lock_irq(&lo->lo_work_lock);

	if (queue_on_root_worker(cmd->blkcg_css))
		goto queue_work;

	node = &lo->worker_tree.rb_node;

	while (*node) {
		parent = *node;
		cur_worker = container_of(*node, struct loop_worker, rb_node);
		if (cur_worker->blkcg_css == cmd->blkcg_css) {
			worker = cur_worker;
			break;
		} else if ((long)cur_worker->blkcg_css < (long)cmd->blkcg_css)
		{
			node = &(*node)->rb_left;
		} else {
			node = &(*node)->rb_right;
		}
	}
	if (worker)
		goto queue_work;

	worker = kzalloc(sizeof(struct loop_worker), GFP_NOWAIT | __GFP_NOWARN);
	/*
	 * In the event we cannot allocate a worker, just queue on the
	 * rootcg worker and issue the I/O as the rootcg
	 */
	if (!worker)
	{
		cmd->blkcg_css = NULL;
		if (cmd->memcg_css)
			css_put(cmd->memcg_css);
		cmd->memcg_css = NULL;
		goto queue_work;
	}

	worker->blkcg_css = cmd->blkcg_css;
	css_get(worker->blkcg_css);
	INIT_WORK(&worker->work, loop_workfn);
	INIT_LIST_HEAD(&worker->cmd_list);
	INIT_LIST_HEAD(&worker->idle_list);
	worker->lo = lo;
	rb_link_node(&worker->rb_node, parent, node);
	rb_insert_color(&worker->rb_node, &lo->worker_tree);
	queue_work:
	if (worker)
	{
		/*
		 * We need to remove from the idle list here while
		 * holding the lock so that the idle timer doesn't
		 * free the worker
		 */
		if (!list_empty(&worker->idle_list))
			list_del_init(&worker->idle_list);
		work = &worker->work;
		cmd_list = &worker->cmd_list;
	} else
	{
		work = &lo->rootcg_work;
		cmd_list = &lo->rootcg_cmd_list;
	}
	list_add_tail(&cmd->list_entry, cmd_list);
	queue_work(lo->workqueue, work);
	spin_unlock_irq(&lo->lo_work_lock);
}
